-- Apply after billing and recovery migrations as migration owner.
BEGIN;
CREATE TABLE IF NOT EXISTS public.gc_evaluation_claims (
    customer_id text PRIMARY KEY REFERENCES public.gc_customers(id),
    subscription_id text NOT NULL UNIQUE REFERENCES public.gc_subscriptions(id),
    installation_hash text NOT NULL UNIQUE CHECK(installation_hash ~ '^[0-9A-F]{64}$'),
    terms_hash text NOT NULL CHECK(terms_hash ~ '^[0-9a-f]{64}$'),
    claimed_utc bigint NOT NULL CHECK(claimed_utc BETWEEN 1 AND 4102444800),
    expires_utc bigint NOT NULL CHECK(expires_utc>claimed_utc AND expires_utc-claimed_utc<=2592000)
);
DO $$
BEGIN
    IF EXISTS(SELECT 1 FROM public.gc_subscriptions s
        JOIN public.gc_issuer_allocations a ON a.subscription_id=s.id
        WHERE s.edition='evaluation' AND NOT EXISTS(
            SELECT 1 FROM public.gc_evaluation_claims c WHERE c.subscription_id=s.id
              AND c.installation_hash=a.installation_hash))
    THEN RAISE EXCEPTION 'existing evaluation requires independently reconciled historical claim before migration';
    END IF;
END $$;
REVOKE ALL ON public.gc_evaluation_claims FROM PUBLIC;
GRANT SELECT ON public.gc_evaluation_claims TO gc_issuer_runtime,gc_recovery_reader;
GRANT INSERT ON public.gc_evaluation_claims TO gc_issuer_runtime;
COMMIT;
