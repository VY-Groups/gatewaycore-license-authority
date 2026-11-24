-- Manual offline commercial billing; apply as migration owner after rotation
-- and recovery roles. No stored card data, gateway credentials or network calls.
BEGIN;
CREATE OR REPLACE FUNCTION public.gc_billing_terms(p_subscription text,p_renewal uuid)
RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
    SELECT encode(sha256(convert_to(
      CASE WHEN p_renewal IS NULL THEN jsonb_build_array(s.id,s.customer_id,s.deployment_id,
        s.edition,s.max_nodes,s.max_sites,floor(extract(epoch FROM s.expires_at))::bigint,
        to_jsonb(s.features))
      ELSE jsonb_build_array(j.proposed_terms->>'LicenseId',j.proposed_terms->>'CustomerId',
        j.proposed_terms->>'DeploymentId',j.proposed_terms->>'Edition',
        (j.proposed_terms->>'MaxNodes')::int,(j.proposed_terms->>'MaxSites')::int,
        (j.proposed_terms->>'ExpiresAt')::bigint,j.proposed_terms->'Features') END::text,'UTF8')),'hex')
    FROM public.gc_subscriptions s
    LEFT JOIN public.gc_license_jobs j ON j.id=p_renewal AND j.subscription_id=s.id
      AND j.kind='renew_terms' AND j.expected_terms_revision=s.terms_revision
      AND j.state IN ('pending','approved')
    WHERE s.id=p_subscription AND (p_renewal IS NULL OR j.id IS NOT NULL);
$$;
REVOKE ALL ON FUNCTION public.gc_billing_terms(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_billing_terms(text,uuid)
  TO gc_portal_requester,gc_portal_reviewer,gc_issuer_runtime;
CREATE TABLE IF NOT EXISTS public.gc_billing_invoices (
    id uuid PRIMARY KEY,
    subscription_id text NOT NULL REFERENCES public.gc_subscriptions(id),
    renewal_job_id uuid REFERENCES public.gc_license_jobs(id),
    terms_hash text NOT NULL CHECK(terms_hash ~ '^[0-9a-f]{64}$'),
    currency text NOT NULL CHECK(currency IN ('INR','USD','EUR','GBP','AUD','CAD','SGD','AED')),
    amount_minor bigint NOT NULL CHECK(amount_minor BETWEEN 1 AND 1000000000000),
    requested_by text NOT NULL CHECK(requested_by ~ '^[A-Za-z0-9_-]{1,80}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','paid','void')),
    decided_by text,
    decided_at timestamptz,
    payment_reference text UNIQUE CHECK(payment_reference ~ '^[A-Za-z0-9_.:/-]{1,120}$'),
    paid_minor bigint,
    CHECK ((state='pending' AND decided_by IS NULL AND decided_at IS NULL AND payment_reference IS NULL AND paid_minor IS NULL)
      OR (state='paid' AND decided_by IS NOT NULL AND decided_by<>requested_by AND decided_at IS NOT NULL
          AND payment_reference IS NOT NULL AND paid_minor=amount_minor AND paid_minor IS NOT NULL)
      OR (state='void' AND decided_by IS NOT NULL AND decided_by<>requested_by AND decided_at IS NOT NULL
          AND payment_reference IS NULL AND paid_minor IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS gc_billing_one_live_terms ON public.gc_billing_invoices(subscription_id,terms_hash)
  WHERE state IN ('pending','paid');
CREATE OR REPLACE FUNCTION public.gc_guard_invoice() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.state<>'pending' OR NEW.terms_hash IS DISTINCT FROM
       public.gc_billing_terms(NEW.subscription_id,NEW.renewal_job_id) THEN
      RAISE EXCEPTION 'invoice must reference exact current/proposed terms' USING ERRCODE='23514';
    END IF;
  ELSE
    IF OLD.state<>'pending' OR NEW.state NOT IN ('paid','void') OR
       (to_jsonb(OLD)-ARRAY['state','decided_by','decided_at','payment_reference','paid_minor']) IS DISTINCT FROM
       (to_jsonb(NEW)-ARRAY['state','decided_by','decided_at','payment_reference','paid_minor']) THEN
      RAISE EXCEPTION 'invoice is immutable except one independent decision' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS gc_guard_invoice ON public.gc_billing_invoices;
CREATE TRIGGER gc_guard_invoice BEFORE INSERT OR UPDATE ON public.gc_billing_invoices
  FOR EACH ROW EXECUTE FUNCTION public.gc_guard_invoice();
REVOKE ALL ON public.gc_billing_invoices FROM PUBLIC;
GRANT SELECT ON public.gc_billing_invoices TO gc_portal_requester,gc_portal_reviewer,gc_issuer_runtime,gc_recovery_reader;
GRANT INSERT(id,subscription_id,renewal_job_id,terms_hash,currency,amount_minor,requested_by)
  ON public.gc_billing_invoices TO gc_portal_requester;
GRANT UPDATE(state,decided_by,decided_at,payment_reference,paid_minor)
  ON public.gc_billing_invoices TO gc_portal_reviewer;
COMMIT;
