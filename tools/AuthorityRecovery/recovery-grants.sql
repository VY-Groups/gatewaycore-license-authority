-- Apply after authority rotation migration, as database migration owner.
-- Provision gc_recovery_reader as a separate non-owner LOGIN role, with
-- its own credential and no memberships in portal/issuer roles.
BEGIN;
GRANT SELECT ON public.gc_customers,public.gc_subscriptions,public.gc_license_jobs,
  public.gc_issuer_authority,public.gc_issuer_allocations,public.gc_issuer_results,
  public.gc_issuer_key_history,public.gc_portal_audit TO gc_recovery_reader;
COMMIT;
