import { expect, it } from 'vitest'
import { managementWarningDetails } from './management_status'

it('reports persistence failure without treating an applied operation as failed', () => {
  const outcome = { runtime_applied: true, persistence_warning: 'disk full' }
  expect(managementWarningDetails(outcome, key => key)).toBe('management_persistence_warning: disk full')
  expect(outcome.runtime_applied).toBe(true)
})

it('includes reconciliation errors independently and clears successful outcomes', () => {
  expect(managementWarningDetails({ runtime_applied: true }, key => key)).toBe('')
  expect(managementWarningDetails({ runtime_applied: false, persistence_warning: 'disk full', reconciliation_warning: 'state unknown' }, key => key))
    .toBe('management_persistence_warning: disk full\nmanagement_reconciliation_warning: state unknown')
})
