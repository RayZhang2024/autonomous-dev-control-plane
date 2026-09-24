# Issue #40 v0.5 §17 adversarial scenario evidence

Each frozen scenario is mapped once to the regression(s) that directly exercise
its boundary and outcome. The G8 integration regressions are included where
they exercise the corresponding end-to-end behavior.

Scenario 01 → `tests/trusted/test_gates.py::test_authenticated_control_state_request_rejects_exact_request_from_untrusted_channel`; `tests/trusted/test_gates.py::test_control_state_rejects_transaction_tampered_after_fixture_transport_authentication`
Scenario 02 → `tests/trusted/test_gates.py::test_publication_or_merge_context_cannot_submit_canonical_mutation[publication]`
Scenario 03 → `tests/trusted/test_gates.py::test_publication_or_merge_context_cannot_submit_canonical_mutation[merge]`
Scenario 04 → `tests/trusted/test_gates.py::test_authenticated_control_state_request_rejects_stale_t_runtime_epoch`; `tests/trusted/test_gates.py::test_control_state_rejects_request_with_mismatched_declared_role_identity`
Scenario 05 → `tests/trusted/test_gates.py::test_control_state_rejects_request_with_mismatched_declared_role_identity`; `tests/trusted/test_gates.py::test_authenticated_control_state_request_rejects_stale_t_runtime_epoch`
Scenario 06 → `tests/trusted/test_gates.py::test_control_state_rejects_transaction_tampered_after_fixture_transport_authentication`
Scenario 07 → `tests/integration/test_g8_adversarial_control_plane.py::test_g8_08_exact_replay_never_duplicates_effect_or_lends_marker_to_other_operation`; `tests/trusted/test_gates.py::test_audit_identity_is_canonical_idempotent_and_conflict_detecting`
Scenario 08 → `tests/trusted/test_gates.py::test_prepared_start_constructor_is_closed`; `tests/trusted/test_gates.py::test_candidate_t_prepared_abort_wins_and_cannot_seal_or_start`
Scenario 09 → `tests/trusted/test_gates.py::test_prepared_effect_cannot_return_from_consumed`; `tests/trusted/test_gates.py::test_prepared_start_to_publication_and_one_use_continuation`
Scenario 10 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`; `tests/trusted/test_gates.py::test_publication_gate_cannot_route_merge_continuation`
Scenario 11 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 12 → `tests/trusted/test_gates.py::test_publication_and_merge_runtimes_have_separate_candidate_role_slots`; `tests/trusted/test_gates.py::test_capabilities_cannot_be_minted_by_callers`
Scenario 13 → `tests/trusted/test_gates.py::test_candidate_gate_entrypoints_receive_only_role_specific_client_contracts`; `tests/trusted/test_gates.py::test_publication_and_merge_runtimes_have_separate_candidate_role_slots`
Scenario 14 → `tests/integration/test_g8_adversarial_control_plane.py::test_g8_05_target_movement_before_start_conflicts_without_effect`; `tests/trusted/test_gates.py::test_manual_same_sha_candidate_branch_conflicts_before_start`
Scenario 15 → `tests/trusted/test_gates.py::test_target_mutation_cannot_linearize_across_prepared_start_and_effect`; `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery`
Scenario 16 → `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery[cas-failure]`; `tests/integration/test_g8_adversarial_control_plane.py::test_g8_09a_prepared_without_marker_releases_and_fails_without_replay`
Scenario 17 → `tests/trusted/test_gates.py::test_target_effect_audit_failure_preserves_marker_and_restart_reconciles_without_replay`; `tests/integration/test_g8_adversarial_control_plane.py::test_g8_09b_consumed_exact_marker_reconciles_succeeded_without_replay`
Scenario 18 → `tests/trusted/test_gates.py::test_restart_preserves_fixture_authority_but_rotates_capabilities`; `tests/trusted/test_gates.py::test_runtime_replacement_waits_for_live_lease_and_retires_old_runtime`
Scenario 19 → `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery[cas-failure]`; `tests/trusted/test_gates.py::test_candidate_t_publication_start_uses_authenticated_roles_not_legacy_runtime`
Scenario 20 → `tests/trusted/test_gates.py::test_publication_or_merge_context_cannot_submit_canonical_mutation[publication]`; `tests/trusted/test_gates.py::test_publication_or_merge_context_cannot_submit_canonical_mutation[merge]`
Scenario 21 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 22 → `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery`; `tests/trusted/test_gates.py::test_target_mutation_cannot_linearize_across_prepared_start_and_effect`
Scenario 23 → `tests/trusted/test_gates.py::test_candidate_gate_entrypoints_receive_only_role_specific_client_contracts`; `tests/trusted/test_gates.py::test_f_read_verify_projection_exposes_only_explicit_observation_operations`
Scenario 24 → `tests/integration/test_g8_adversarial_control_plane.py::test_g8_05_target_movement_before_start_conflicts_without_effect`; `tests/integration/test_g8_adversarial_control_plane.py::test_g8_08_exact_replay_never_duplicates_effect_or_lends_marker_to_other_operation`; `tests/integration/test_g8_adversarial_control_plane.py::test_g8_10a_authoritative_cancellation_first_blocks_protected_start`; `tests/integration/test_g8_adversarial_control_plane.py::test_g8_09c_contradictory_marker_postcondition_is_indeterminate`
Scenario 25 → `tests/trusted/test_gates.py::test_authenticated_control_state_request_rejects_exact_request_from_untrusted_channel`; `tests/trusted/test_gates.py::test_unauthenticated_t_to_p_prepare_request_cannot_create_prepared_authority`
Scenario 26 → `tests/trusted/test_gates.py::test_publication_or_merge_context_cannot_submit_canonical_mutation[publication]`; `tests/trusted/test_gates.py::test_publication_or_merge_context_cannot_submit_canonical_mutation[merge]`
Scenario 27 → `tests/trusted/test_gates.py::test_authenticated_control_state_request_rejects_stale_t_runtime_epoch`; `tests/trusted/test_gates.py::test_restart_same_generation_rotates_runtime_identity_in_audit`
Scenario 28 → `tests/trusted/test_gates.py::test_control_state_rejects_request_with_mismatched_declared_role_identity`; `tests/trusted/test_gates.py::test_protected_gate_rejects_request_identity_or_destination_mismatch[declared_t]`
Scenario 29 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 30 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 31 → `tests/trusted/test_gates.py::test_candidate_t_prepared_abort_wins_and_cannot_seal_or_start`
Scenario 32 → `tests/trusted/test_gates.py::test_missing_or_mismatched_durable_start_fails_recovery_closed`; `tests/trusted/test_gates.py::test_prepared_start_dependency_identity_contradiction_fails_closed`
Scenario 33 → `tests/trusted/test_gates.py::test_start_binding_changes_with_action_fence`; `tests/trusted/test_gates.py::test_missing_or_mismatched_durable_start_fails_recovery_closed`
Scenario 34 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 35 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 36 → `tests/trusted/test_gates.py::test_same_thread_fenced_fixture_mutation_is_rejected_deterministically`; `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery`
Scenario 37 → `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery`; `tests/trusted/test_gates.py::test_target_mutation_cannot_linearize_across_prepared_start_and_effect`
Scenario 38 → `tests/trusted/test_gates.py::test_candidate_gate_entrypoints_receive_only_role_specific_client_contracts`; `tests/trusted/test_gates.py::test_publication_and_merge_runtimes_have_separate_candidate_role_slots`
Scenario 39 → `tests/trusted/test_gates.py::test_candidate_t_concurrent_prepared_abort_and_seal_have_one_f_linearized_winner`
Scenario 40 → `tests/trusted/test_gates.py::test_candidate_t_prepared_abort_wins_and_cannot_seal_or_start`; `tests/trusted/test_gates.py::test_candidate_t_concurrent_prepared_abort_and_seal_have_one_f_linearized_winner`
Scenario 41 → `tests/trusted/test_gates.py::test_candidate_t_seal_wins_and_ordinary_abort_is_rejected`; `tests/trusted/test_gates.py::test_candidate_t_concurrent_prepared_abort_and_seal_have_one_f_linearized_winner`
Scenario 42 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`; `tests/trusted/test_gates.py::test_candidate_t_merge_start_uses_authenticated_roles_not_legacy_runtime`
Scenario 43 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 44 → `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery[cas-failure]`
Scenario 45 → `tests/trusted/test_gates.py::test_candidate_gate_entrypoints_receive_only_role_specific_client_contracts`; `tests/trusted/test_gates.py::test_candidate_t_seal_wins_and_ordinary_abort_is_rejected`
Scenario 46 → `tests/trusted/test_gates.py::test_candidate_gate_entrypoints_receive_only_role_specific_client_contracts`
Scenario 47 → `tests/trusted/test_gates.py::test_candidate_t_publication_start_uses_authenticated_roles_not_legacy_runtime`; `tests/trusted/test_gates.py::test_candidate_t_merge_start_uses_authenticated_roles_not_legacy_runtime`
Scenario 48 → `tests/trusted/test_gates.py::test_candidate_t_prepared_abort_wins_and_cannot_seal_or_start`; `tests/trusted/test_gates.py::test_c_rejects_start_request_not_bound_to_exact_authoritative_start_held[operation]`; `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery[cas-failure]`
Scenario 49 → `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery[cas-failure]`
Scenario 50 → `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery[response-lost]`
Scenario 51 → `tests/trusted/test_gates.py::test_publication_and_merge_runtimes_have_separate_candidate_role_slots`; `tests/trusted/test_gates.py::test_candidate_t_seal_wins_and_ordinary_abort_is_rejected`
Scenario 52 → `tests/trusted/test_gates.py::test_start_binding_changes_with_action_fence`; `tests/trusted/test_gates.py::test_candidate_t_publication_start_uses_authenticated_roles_not_legacy_runtime`
Scenario 53 → `tests/trusted/test_gates.py::test_candidate_t_publication_start_uses_authenticated_roles_not_legacy_runtime`; `tests/trusted/test_gates.py::test_candidate_t_merge_start_uses_authenticated_roles_not_legacy_runtime`
Scenario 54 → `tests/trusted/test_gates.py::test_missing_or_mismatched_durable_start_fails_recovery_closed`
Scenario 55 → `tests/trusted/test_gates.py::test_missing_or_mismatched_durable_start_fails_recovery_closed`; `tests/trusted/test_gates.py::test_restart_same_generation_rotates_runtime_identity_in_audit`
Scenario 56 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 57 → `tests/trusted/test_gates.py::test_missing_or_mismatched_durable_start_fails_recovery_closed`; `tests/integration/test_g8_adversarial_control_plane.py::test_g8_13_contradictory_marked_merge_state_recovers_indeterminate`
Scenario 58 → `tests/trusted/test_gates.py::test_missing_or_mismatched_durable_start_fails_recovery_closed`; `tests/trusted/test_gates.py::test_recovery_reuses_exact_frozen_dependencies_and_audits_them`
Scenario 59 → `tests/trusted/test_gates.py::test_unauthenticated_t_to_p_seal_cannot_start_operation`; `tests/trusted/test_gates.py::test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery[cas-failure]`
Scenario 60 → `tests/trusted/test_gates.py::test_candidate_gate_entrypoints_receive_only_role_specific_client_contracts`; `tests/trusted/test_gates.py::test_publication_and_merge_runtimes_have_separate_candidate_role_slots`
Scenario 61 → `tests/trusted/test_gates.py::test_unauthenticated_t_to_p_prepare_request_cannot_create_prepared_authority`
Scenario 62 → `tests/trusted/test_gates.py::test_unauthenticated_t_to_m_prepare_request_cannot_create_prepared_authority`
Scenario 63 → `tests/trusted/test_gates.py::test_protected_gate_rejects_request_identity_or_destination_mismatch[declared_t]`; `tests/trusted/test_gates.py::test_p_and_m_do_not_self_issue_authenticated_t_channel_contexts`
Scenario 64 → `tests/trusted/test_gates.py::test_restart_same_generation_rotates_runtime_identity_in_audit`; `tests/trusted/test_gates.py::test_runtime_replacement_waits_for_live_lease_and_retires_old_runtime`
Scenario 65 → `tests/trusted/test_gates.py::test_protected_gate_rejects_request_identity_or_destination_mismatch[declared_t]`
Scenario 66 → `tests/trusted/test_gates.py::test_protected_gate_rejects_request_identity_or_destination_mismatch[destination]`
Scenario 67 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 68 → `tests/trusted/test_gates.py::test_f_role_clients_reject_cross_role_prepared_authority_commands`
Scenario 69 → `tests/trusted/test_gates.py::test_unauthenticated_t_to_p_abort_cannot_release_prepared_authority`
Scenario 70 → `tests/trusted/test_gates.py::test_unauthenticated_t_to_p_seal_cannot_start_operation`
Scenario 71 → `tests/trusted/test_gates.py::test_p_and_m_do_not_self_issue_authenticated_t_channel_contexts`; `tests/trusted/test_gates.py::test_candidate_t_publication_start_uses_authenticated_roles_not_legacy_runtime`
Scenario 72 → `tests/trusted/test_gates.py::test_prepared_start_to_publication_and_one_use_continuation`; `tests/integration/test_g8_adversarial_control_plane.py::test_g8_08_exact_replay_never_duplicates_effect_or_lends_marker_to_other_operation`
Scenario 73 → `tests/trusted/test_gates.py::test_candidate_t_publication_start_uses_authenticated_roles_not_legacy_runtime`; `tests/trusted/test_gates.py::test_candidate_t_merge_start_uses_authenticated_roles_not_legacy_runtime`
