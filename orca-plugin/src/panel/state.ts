import type {
  L7PolicySuggestion,
  PolicyInspectionReport,
  SandboxDoctorReport,
} from '../types.ts'

export type PanelTab = 'egress' | 'filesystem' | 'setup' | 'settings'

export const panelState = {
  currentReport: null as PolicyInspectionReport | null,
  doctorReport: null as SandboxDoctorReport | null,
  runningDoctor: false,
  activeTab: 'egress' as PanelTab,
  searchFilter: '',
  actionFilter: 'all',
  egressSearch: '',
  togglingSandbox: false,
  lastL7Suggestion: null as L7PolicySuggestion | null,
  openApps: new Set<string>(),
  openCliRules: new Set<string>(),
  openEgress: new Set<string>(),
  openSections: new Set<string>(),
  closedSections: new Set<string>(),
  openSystemItems: new Set<string>(),
}
