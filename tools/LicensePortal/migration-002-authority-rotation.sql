-- Apply after schema.sql and runtime role creation, as migration owner.
BEGIN;
DO $$
DECLARE item record; n integer := 0;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.gc_license_jobs'::regclass AND conname='gc_license_jobs_kind_v2') THEN
    FOR item IN SELECT conname FROM pg_constraint
      WHERE conrelid='public.gc_license_jobs'::regclass AND contype='c'
        AND pg_get_constraintdef(oid) LIKE '%renew_terms%'
    LOOP
      EXECUTE format('ALTER TABLE public.gc_license_jobs DROP CONSTRAINT %I',item.conname);
      n := n + 1;
    END LOOP;
    IF n <> 2 THEN RAISE EXCEPTION 'unexpected job schema; migration aborted'; END IF;
    ALTER TABLE public.gc_license_jobs ADD CONSTRAINT gc_license_jobs_kind_v2
      CHECK(kind IN ('issue','revoke','renew_terms','rotate_authority'));
    ALTER TABLE public.gc_license_jobs ADD CONSTRAINT gc_license_jobs_payload_v2 CHECK(
      (kind='issue' AND request_id IS NOT NULL AND installation_hash IS NOT NULL AND site_id IS NOT NULL
        AND request_file IS NOT NULL AND allocation_id IS NULL AND proposed_terms IS NULL)
      OR (kind='revoke' AND allocation_id IS NOT NULL AND request_id IS NULL AND installation_hash IS NULL
        AND site_id IS NULL AND request_file IS NULL AND proposed_terms IS NULL)
      OR (kind IN ('renew_terms','rotate_authority') AND proposed_terms IS NOT NULL AND allocation_id IS NULL
        AND request_id IS NULL AND installation_hash IS NULL AND site_id IS NULL AND request_file IS NULL));
  END IF;
END $$;
CREATE TABLE IF NOT EXISTS public.gc_issuer_key_history (
  subscription_id text NOT NULL REFERENCES public.gc_subscriptions(id),
  key_id text NOT NULL,
  public_key_hash text NOT NULL,
  rotation_job uuid NOT NULL REFERENCES public.gc_license_jobs(id),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(subscription_id,key_id),
  UNIQUE(subscription_id,public_key_hash)
);
REVOKE ALL ON public.gc_issuer_key_history FROM PUBLIC,gc_portal_requester,gc_portal_reviewer,gc_issuer_runtime;
GRANT SELECT ON public.gc_issuer_key_history TO gc_issuer_runtime;
-- The worker may not directly update the authority row. Only this narrow
-- approved transition is executable; the separate worker checks private key possession.
CREATE OR REPLACE FUNCTION public.gc_rotate_authority(
  p_job uuid,p_old_id text,p_old_hash text,p_new_id text,p_new_hash text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j record; v_revision bigint;
BEGIN
  SELECT * INTO j FROM public.gc_license_jobs WHERE id=p_job AND kind='rotate_authority'
    AND state='approved' AND approved_by<>requested_by AND approved_at IS NOT NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'rotation not independently approved' USING ERRCODE='23514'; END IF;
  SELECT terms_revision INTO v_revision FROM public.gc_subscriptions WHERE id=j.subscription_id FOR UPDATE;
  IF v_revision IS DISTINCT FROM j.expected_terms_revision
    OR EXISTS(SELECT 1 FROM public.gc_issuer_results WHERE job_id=p_job)
    OR p_old_id=p_new_id OR p_old_hash=p_new_hash
    OR p_new_id !~ '^[A-Za-z0-9_-]{1,80}$' OR p_new_hash !~ '^[A-F0-9]{64}$'
    OR j.proposed_terms->>'NewKeyId' IS DISTINCT FROM p_new_id
    OR j.proposed_terms->>'NewPublicKeySha256' IS DISTINCT FROM p_new_hash
    OR j.proposed_terms->>'CustomerTrustStaged' IS DISTINCT FROM 'true'
    OR NOT EXISTS(SELECT 1 FROM public.gc_issuer_authority WHERE subscription_id=j.subscription_id
                  AND key_id=p_old_id AND public_key_hash=p_old_hash)
  THEN RAISE EXCEPTION 'rotation conflicts with authority or approved terms' USING ERRCODE='23514'; END IF;
  INSERT INTO public.gc_issuer_key_history(subscription_id,key_id,public_key_hash,rotation_job)
    VALUES(j.subscription_id,p_old_id,p_old_hash,p_job) ON CONFLICT(subscription_id,key_id) DO NOTHING;
  INSERT INTO public.gc_issuer_key_history(subscription_id,key_id,public_key_hash,rotation_job)
    VALUES(j.subscription_id,p_new_id,p_new_hash,p_job);
  UPDATE public.gc_issuer_authority SET key_id=p_new_id,public_key_hash=p_new_hash WHERE subscription_id=j.subscription_id;
  UPDATE public.gc_subscriptions SET terms_revision=terms_revision+1 WHERE id=j.subscription_id;
END $$;
REVOKE ALL ON FUNCTION public.gc_rotate_authority(uuid,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_rotate_authority(uuid,text,text,text,text) TO gc_issuer_runtime;
COMMIT;
