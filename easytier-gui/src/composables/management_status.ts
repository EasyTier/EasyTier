export interface OperationOutcome {
  runtime_applied: boolean
  persistence_warning?: string | null
  reconciliation_warning?: string | null
}

export interface ManagementStatus {
  running_instances: string[]
  desired_enabled: string[]
  runtime_state_known: boolean
  last_outcome: OperationOutcome
}

export function managementWarningDetails(outcome: OperationOutcome, translate: (key: string) => string): string {
  const warnings: string[] = []
  if (outcome.persistence_warning)
    warnings.push(`${translate('management_persistence_warning')}: ${outcome.persistence_warning}`)
  if (outcome.reconciliation_warning)
    warnings.push(`${translate('management_reconciliation_warning')}: ${outcome.reconciliation_warning}`)
  return warnings.join('\n')
}
