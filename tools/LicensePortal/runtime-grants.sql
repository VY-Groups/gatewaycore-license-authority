-- Apply as the migration owner, after independently provisioning these
-- three non-owner, non-superuser LOGIN roles with no inherited write privileges.
-- Do not grant one runtime role membership in another.
BEGIN;
REVOKE ALL ON gc_customers,gc_subscriptions,gc_license_jobs,gc_portal_audit,
  gc_issuer_authority,gc_issuer_allocations,gc_issuer_results FROM PUBLIC;
REVOKE ALL ON SEQUENCE gc_portal_audit_id_seq FROM PUBLIC;
GRANT SELECT ON gc_customers,gc_subscriptions,gc_license_jobs,gc_issuer_results
  TO gc_portal_requester,gc_portal_reviewer;
GRANT INSERT (id,name) ON gc_customers TO gc_portal_requester;
GRANT INSERT (id,customer_id,deployment_id,edition,max_nodes,max_sites,expires_at,features)
  ON gc_subscriptions TO gc_portal_requester;
GRANT INSERT (id,subscription_id,kind,expected_terms_revision,proposed_terms,site_id,
  request_id,installation_hash,request_file,allocation_id,requested_by)
  ON gc_license_jobs TO gc_portal_requester;
GRANT UPDATE (state,approved_by,approved_at) ON gc_license_jobs TO gc_portal_reviewer;
GRANT SELECT ON gc_license_jobs,gc_subscriptions,gc_issuer_authority,gc_issuer_allocations,gc_issuer_results
  TO gc_issuer_runtime;
GRANT UPDATE (edition,max_nodes,max_sites,expires_at,features,terms_revision)
  ON gc_subscriptions TO gc_issuer_runtime;
GRANT INSERT ON gc_issuer_authority,gc_issuer_allocations,gc_issuer_results TO gc_issuer_runtime;
GRANT UPDATE (revision,last_expiry,revocation_envelope) ON gc_issuer_allocations TO gc_issuer_runtime;
GRANT INSERT (actor,action,subject) ON gc_portal_audit
  TO gc_portal_requester,gc_portal_reviewer,gc_issuer_runtime;
GRANT USAGE ON SEQUENCE gc_portal_audit_id_seq
  TO gc_portal_requester,gc_portal_reviewer,gc_issuer_runtime;

-- Enforce a single decision transition, even for an accidental raw SQL update.
CREATE OR REPLACE FUNCTION gc_guard_job_decision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.state <> 'pending' OR NEW.state NOT IN ('approved','rejected')
    OR NEW.approved_by IS NULL OR NEW.approved_by = OLD.requested_by
    OR NEW.approved_at IS NULL
    OR (to_jsonb(NEW) - ARRAY['state','approved_by','approved_at'])
       IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state','approved_by','approved_at'])
  THEN RAISE EXCEPTION 'invalid immutable job decision' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS gc_guard_job_decision ON gc_license_jobs;
CREATE TRIGGER gc_guard_job_decision BEFORE UPDATE ON gc_license_jobs
  FOR EACH ROW EXECUTE FUNCTION gc_guard_job_decision();
COMMIT;
