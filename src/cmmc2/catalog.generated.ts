// GENERATED FILE - DO NOT EDIT.
// Run `pnpm run catalog:build` to regenerate. CI fails if this file is stale.
//
// Derived from NIST SP 800-171 Rev. 2 (upd1) - Security Requirements (CSV)
//   https://csrc.nist.gov/files/pubs/sp/800/171/r2/upd1/final/docs/sp800-171r2-security-reqs.csv
//   retrieved 2026-07-30, sha256 0f4d59413bbcc9998da80495ce46ebfe0475e392803c4d2ed38d9941d83f138d
//   US Government work, public domain (17 U.S.C. 105)
//
// CMMC 2.0 Level 2 practices correspond 1:1 to the 110 security
// requirements of NIST SP 800-171 Rev 2. Practice IDs are derived as
// <DOMAIN>.L2-<requirement>, with the domain abbreviation taken from the
// SP 800-53 family code for that family.

/** How completely a requirement is stated in SP 800-171: a base requirement or one derived from it. */
export type Cmmc2RequirementKind = 'basic' | 'derived'

/** The revision of NIST SP 800-171 a practice is defined against. */
export type Cmmc2Revision = 'rev2'

/** CMMC 2.0 Level 2 practice identifiers. All 110 of them. */
export type Cmmc2PracticeId =
  | 'AC.L2-3.1.1'
  | 'AC.L2-3.1.2'
  | 'AC.L2-3.1.3'
  | 'AC.L2-3.1.4'
  | 'AC.L2-3.1.5'
  | 'AC.L2-3.1.6'
  | 'AC.L2-3.1.7'
  | 'AC.L2-3.1.8'
  | 'AC.L2-3.1.9'
  | 'AC.L2-3.1.10'
  | 'AC.L2-3.1.11'
  | 'AC.L2-3.1.12'
  | 'AC.L2-3.1.13'
  | 'AC.L2-3.1.14'
  | 'AC.L2-3.1.15'
  | 'AC.L2-3.1.16'
  | 'AC.L2-3.1.17'
  | 'AC.L2-3.1.18'
  | 'AC.L2-3.1.19'
  | 'AC.L2-3.1.20'
  | 'AC.L2-3.1.21'
  | 'AC.L2-3.1.22'
  | 'AT.L2-3.2.1'
  | 'AT.L2-3.2.2'
  | 'AT.L2-3.2.3'
  | 'AU.L2-3.3.1'
  | 'AU.L2-3.3.2'
  | 'AU.L2-3.3.3'
  | 'AU.L2-3.3.4'
  | 'AU.L2-3.3.5'
  | 'AU.L2-3.3.6'
  | 'AU.L2-3.3.7'
  | 'AU.L2-3.3.8'
  | 'AU.L2-3.3.9'
  | 'CM.L2-3.4.1'
  | 'CM.L2-3.4.2'
  | 'CM.L2-3.4.3'
  | 'CM.L2-3.4.4'
  | 'CM.L2-3.4.5'
  | 'CM.L2-3.4.6'
  | 'CM.L2-3.4.7'
  | 'CM.L2-3.4.8'
  | 'CM.L2-3.4.9'
  | 'IA.L2-3.5.1'
  | 'IA.L2-3.5.2'
  | 'IA.L2-3.5.3'
  | 'IA.L2-3.5.4'
  | 'IA.L2-3.5.5'
  | 'IA.L2-3.5.6'
  | 'IA.L2-3.5.7'
  | 'IA.L2-3.5.8'
  | 'IA.L2-3.5.9'
  | 'IA.L2-3.5.10'
  | 'IA.L2-3.5.11'
  | 'IR.L2-3.6.1'
  | 'IR.L2-3.6.2'
  | 'IR.L2-3.6.3'
  | 'MA.L2-3.7.1'
  | 'MA.L2-3.7.2'
  | 'MA.L2-3.7.3'
  | 'MA.L2-3.7.4'
  | 'MA.L2-3.7.5'
  | 'MA.L2-3.7.6'
  | 'MP.L2-3.8.1'
  | 'MP.L2-3.8.2'
  | 'MP.L2-3.8.3'
  | 'MP.L2-3.8.4'
  | 'MP.L2-3.8.5'
  | 'MP.L2-3.8.6'
  | 'MP.L2-3.8.7'
  | 'MP.L2-3.8.8'
  | 'MP.L2-3.8.9'
  | 'PS.L2-3.9.1'
  | 'PS.L2-3.9.2'
  | 'PE.L2-3.10.1'
  | 'PE.L2-3.10.2'
  | 'PE.L2-3.10.3'
  | 'PE.L2-3.10.4'
  | 'PE.L2-3.10.5'
  | 'PE.L2-3.10.6'
  | 'RA.L2-3.11.1'
  | 'RA.L2-3.11.2'
  | 'RA.L2-3.11.3'
  | 'CA.L2-3.12.1'
  | 'CA.L2-3.12.2'
  | 'CA.L2-3.12.3'
  | 'CA.L2-3.12.4'
  | 'SC.L2-3.13.1'
  | 'SC.L2-3.13.2'
  | 'SC.L2-3.13.3'
  | 'SC.L2-3.13.4'
  | 'SC.L2-3.13.5'
  | 'SC.L2-3.13.6'
  | 'SC.L2-3.13.7'
  | 'SC.L2-3.13.8'
  | 'SC.L2-3.13.9'
  | 'SC.L2-3.13.10'
  | 'SC.L2-3.13.11'
  | 'SC.L2-3.13.12'
  | 'SC.L2-3.13.13'
  | 'SC.L2-3.13.14'
  | 'SC.L2-3.13.15'
  | 'SC.L2-3.13.16'
  | 'SI.L2-3.14.1'
  | 'SI.L2-3.14.2'
  | 'SI.L2-3.14.3'
  | 'SI.L2-3.14.4'
  | 'SI.L2-3.14.5'
  | 'SI.L2-3.14.6'
  | 'SI.L2-3.14.7'

/** A single CMMC 2.0 Level 2 practice and its NIST SP 800-171 origin. */
export interface Cmmc2Practice {
  readonly id: Cmmc2PracticeId
  /** Capability domain, e.g. 'System and Communications Protection'. */
  readonly domain: string
  /** Two-letter domain code, e.g. 'SC'. */
  readonly domainAbbrev: string
  /** CMMC level at which the practice is assessed. */
  readonly level: 2
  /** SP 800-171 revision this text is taken from. CMMC Level 2 is pinned to rev2. */
  readonly revision: Cmmc2Revision
  readonly requirementKind: Cmmc2RequirementKind
  /** Corresponding SP 800-171 requirement number, e.g. '3.13.16'. */
  readonly nist800171: string
  /** Requirement text, verbatim from NIST. */
  readonly title: string
}

/** Every CMMC 2.0 Level 2 practice, keyed by identifier. */
export const CMMC2_PRACTICES: Readonly<Record<Cmmc2PracticeId, Cmmc2Practice>> = {
  'AC.L2-3.1.1': {
    id: 'AC.L2-3.1.1',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.1.1',
    title: 'Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).',
  },
  'AC.L2-3.1.2': {
    id: 'AC.L2-3.1.2',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.1.2',
    title: 'Limit system access to the types of transactions and functions that authorized users are permitted to execute.',
  },
  'AC.L2-3.1.3': {
    id: 'AC.L2-3.1.3',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.3',
    title: 'Control the flow of CUI in accordance with approved authorizations.',
  },
  'AC.L2-3.1.4': {
    id: 'AC.L2-3.1.4',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.4',
    title: 'Separate the duties of individuals to reduce the risk of malevolent activity without collusion.',
  },
  'AC.L2-3.1.5': {
    id: 'AC.L2-3.1.5',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.5',
    title: 'Employ the principle of least privilege, including for specific security functions and privileged accounts.',
  },
  'AC.L2-3.1.6': {
    id: 'AC.L2-3.1.6',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.6',
    title: 'Use non-privileged accounts or roles when accessing nonsecurity functions',
  },
  'AC.L2-3.1.7': {
    id: 'AC.L2-3.1.7',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.7',
    title: 'Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.',
  },
  'AC.L2-3.1.8': {
    id: 'AC.L2-3.1.8',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.8',
    title: 'Limit unsuccessful logon attempts.',
  },
  'AC.L2-3.1.9': {
    id: 'AC.L2-3.1.9',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.9',
    title: 'Provide privacy and security notices consistent with applicable CUI rules.',
  },
  'AC.L2-3.1.10': {
    id: 'AC.L2-3.1.10',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.10',
    title: 'Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity',
  },
  'AC.L2-3.1.11': {
    id: 'AC.L2-3.1.11',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.11',
    title: 'Terminate (automatically) a user session after a defined condition.',
  },
  'AC.L2-3.1.12': {
    id: 'AC.L2-3.1.12',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.12',
    title: 'Monitor and control remote access sessions.',
  },
  'AC.L2-3.1.13': {
    id: 'AC.L2-3.1.13',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.13',
    title: 'Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.',
  },
  'AC.L2-3.1.14': {
    id: 'AC.L2-3.1.14',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.14',
    title: 'Route remote access via managed access control points.',
  },
  'AC.L2-3.1.15': {
    id: 'AC.L2-3.1.15',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.15',
    title: 'Authorize remote execution of privileged commands and remote access to security-relevant information.',
  },
  'AC.L2-3.1.16': {
    id: 'AC.L2-3.1.16',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.16',
    title: 'Authorize wireless access prior to allowing such connections',
  },
  'AC.L2-3.1.17': {
    id: 'AC.L2-3.1.17',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.17',
    title: 'Protect wireless access using authentication and encryption',
  },
  'AC.L2-3.1.18': {
    id: 'AC.L2-3.1.18',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.18',
    title: 'Control connection of mobile devices.',
  },
  'AC.L2-3.1.19': {
    id: 'AC.L2-3.1.19',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.19',
    title: 'Encrypt CUI on mobile devices and mobile computing platforms.[23]',
  },
  'AC.L2-3.1.20': {
    id: 'AC.L2-3.1.20',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.20',
    title: 'Verify and control/limit connections to and use of external systems.',
  },
  'AC.L2-3.1.21': {
    id: 'AC.L2-3.1.21',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.21',
    title: 'Limit use of portable storage devices on external systems.',
  },
  'AC.L2-3.1.22': {
    id: 'AC.L2-3.1.22',
    domain: 'Access Control',
    domainAbbrev: 'AC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.1.22',
    title: 'Control CUI posted or processed on publicly accessible systems.',
  },
  'AT.L2-3.2.1': {
    id: 'AT.L2-3.2.1',
    domain: 'Awareness and Training',
    domainAbbrev: 'AT',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.2.1',
    title: 'Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.',
  },
  'AT.L2-3.2.2': {
    id: 'AT.L2-3.2.2',
    domain: 'Awareness and Training',
    domainAbbrev: 'AT',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.2.2',
    title: 'Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.',
  },
  'AT.L2-3.2.3': {
    id: 'AT.L2-3.2.3',
    domain: 'Awareness and Training',
    domainAbbrev: 'AT',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.2.3',
    title: 'Provide security awareness training on recognizing and reporting potential indicators of insider threat.',
  },
  'AU.L2-3.3.1': {
    id: 'AU.L2-3.3.1',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.3.1',
    title: 'Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity',
  },
  'AU.L2-3.3.2': {
    id: 'AU.L2-3.3.2',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.3.2',
    title: 'Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions.',
  },
  'AU.L2-3.3.3': {
    id: 'AU.L2-3.3.3',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.3.3',
    title: 'Review and update logged events.',
  },
  'AU.L2-3.3.4': {
    id: 'AU.L2-3.3.4',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.3.4',
    title: 'Alert in the event of an audit logging process failure.',
  },
  'AU.L2-3.3.5': {
    id: 'AU.L2-3.3.5',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.3.5',
    title: 'Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.',
  },
  'AU.L2-3.3.6': {
    id: 'AU.L2-3.3.6',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.3.6',
    title: 'Provide audit record reduction and report generation to support on-demand analysis and reporting.',
  },
  'AU.L2-3.3.7': {
    id: 'AU.L2-3.3.7',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.3.7',
    title: 'Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records',
  },
  'AU.L2-3.3.8': {
    id: 'AU.L2-3.3.8',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.3.8',
    title: 'Protect audit information and audit logging tools from unauthorized access, modification, and deletion.',
  },
  'AU.L2-3.3.9': {
    id: 'AU.L2-3.3.9',
    domain: 'Audit and Accountability',
    domainAbbrev: 'AU',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.3.9',
    title: 'Limit management of audit logging functionality to a subset of privileged users.',
  },
  'CM.L2-3.4.1': {
    id: 'CM.L2-3.4.1',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.4.1',
    title: 'Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.',
  },
  'CM.L2-3.4.2': {
    id: 'CM.L2-3.4.2',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.4.2',
    title: 'Establish and enforce security configuration settings for information technology products employed in organizational systems.',
  },
  'CM.L2-3.4.3': {
    id: 'CM.L2-3.4.3',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.4.3',
    title: 'Track, review, approve or disapprove, and log changes to organizational systems.',
  },
  'CM.L2-3.4.4': {
    id: 'CM.L2-3.4.4',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.4.4',
    title: 'Analyze the security impact of changes prior to implementation.',
  },
  'CM.L2-3.4.5': {
    id: 'CM.L2-3.4.5',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.4.5',
    title: 'Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.',
  },
  'CM.L2-3.4.6': {
    id: 'CM.L2-3.4.6',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.4.6',
    title: 'Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.',
  },
  'CM.L2-3.4.7': {
    id: 'CM.L2-3.4.7',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.4.7',
    title: 'Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.',
  },
  'CM.L2-3.4.8': {
    id: 'CM.L2-3.4.8',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.4.8',
    title: 'Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.',
  },
  'CM.L2-3.4.9': {
    id: 'CM.L2-3.4.9',
    domain: 'Configuration Management',
    domainAbbrev: 'CM',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.4.9',
    title: 'Control and monitor user-installed software.',
  },
  'IA.L2-3.5.1': {
    id: 'IA.L2-3.5.1',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.5.1',
    title: 'Identify system users, processes acting on behalf of users, and devices.',
  },
  'IA.L2-3.5.2': {
    id: 'IA.L2-3.5.2',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.5.2',
    title: 'Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.',
  },
  'IA.L2-3.5.3': {
    id: 'IA.L2-3.5.3',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.3',
    title: 'Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.[24] [25].',
  },
  'IA.L2-3.5.4': {
    id: 'IA.L2-3.5.4',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.4',
    title: 'Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.',
  },
  'IA.L2-3.5.5': {
    id: 'IA.L2-3.5.5',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.5',
    title: 'Prevent reuse of identifiers for a defined period.',
  },
  'IA.L2-3.5.6': {
    id: 'IA.L2-3.5.6',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.6',
    title: 'Disable identifiers after a defined period of inactivity.',
  },
  'IA.L2-3.5.7': {
    id: 'IA.L2-3.5.7',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.7',
    title: 'Enforce a minimum password complexity and change of characters when new passwords are created.',
  },
  'IA.L2-3.5.8': {
    id: 'IA.L2-3.5.8',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.8',
    title: 'Prohibit password reuse for a specified number of generations.',
  },
  'IA.L2-3.5.9': {
    id: 'IA.L2-3.5.9',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.9',
    title: 'Allow temporary password use for system logons with an immediate change to a permanent password.',
  },
  'IA.L2-3.5.10': {
    id: 'IA.L2-3.5.10',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.10',
    title: 'Store and transmit only cryptographically-protected passwords.',
  },
  'IA.L2-3.5.11': {
    id: 'IA.L2-3.5.11',
    domain: 'Identification and Authentication',
    domainAbbrev: 'IA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.5.11',
    title: 'Obscure feedback of authentication information',
  },
  'IR.L2-3.6.1': {
    id: 'IR.L2-3.6.1',
    domain: 'Incident Response',
    domainAbbrev: 'IR',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.6.1',
    title: 'Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.',
  },
  'IR.L2-3.6.2': {
    id: 'IR.L2-3.6.2',
    domain: 'Incident Response',
    domainAbbrev: 'IR',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.6.2',
    title: 'Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.',
  },
  'IR.L2-3.6.3': {
    id: 'IR.L2-3.6.3',
    domain: 'Incident Response',
    domainAbbrev: 'IR',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.6.3',
    title: 'Test the organizational incident response capability.',
  },
  'MA.L2-3.7.1': {
    id: 'MA.L2-3.7.1',
    domain: 'Maintenance',
    domainAbbrev: 'MA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.7.1',
    title: 'Perform maintenance on organizational systems.[26].',
  },
  'MA.L2-3.7.2': {
    id: 'MA.L2-3.7.2',
    domain: 'Maintenance',
    domainAbbrev: 'MA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.7.2',
    title: 'Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.',
  },
  'MA.L2-3.7.3': {
    id: 'MA.L2-3.7.3',
    domain: 'Maintenance',
    domainAbbrev: 'MA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.7.3',
    title: 'Ensure equipment removed for off-site maintenance is sanitized of any CUI.',
  },
  'MA.L2-3.7.4': {
    id: 'MA.L2-3.7.4',
    domain: 'Maintenance',
    domainAbbrev: 'MA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.7.4',
    title: 'Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.',
  },
  'MA.L2-3.7.5': {
    id: 'MA.L2-3.7.5',
    domain: 'Maintenance',
    domainAbbrev: 'MA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.7.5',
    title: 'Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.',
  },
  'MA.L2-3.7.6': {
    id: 'MA.L2-3.7.6',
    domain: 'Maintenance',
    domainAbbrev: 'MA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.7.6',
    title: 'Supervise the maintenance activities of maintenance personnel without required access authorization.',
  },
  'MP.L2-3.8.1': {
    id: 'MP.L2-3.8.1',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.8.1',
    title: 'Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.',
  },
  'MP.L2-3.8.2': {
    id: 'MP.L2-3.8.2',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.8.2',
    title: 'Limit access to CUI on system media to authorized users',
  },
  'MP.L2-3.8.3': {
    id: 'MP.L2-3.8.3',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.8.3',
    title: 'Sanitize or destroy system media containing CUI before disposal or release for reuse.',
  },
  'MP.L2-3.8.4': {
    id: 'MP.L2-3.8.4',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.8.4',
    title: 'Mark media with necessary CUI markings and distribution limitations.[27]',
  },
  'MP.L2-3.8.5': {
    id: 'MP.L2-3.8.5',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.8.5',
    title: 'Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.',
  },
  'MP.L2-3.8.6': {
    id: 'MP.L2-3.8.6',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.8.6',
    title: 'Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.',
  },
  'MP.L2-3.8.7': {
    id: 'MP.L2-3.8.7',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.8.7',
    title: 'Control the use of removable media on system components.',
  },
  'MP.L2-3.8.8': {
    id: 'MP.L2-3.8.8',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.8.8',
    title: 'Prohibit the use of portable storage devices when such devices have no identifiable owner.',
  },
  'MP.L2-3.8.9': {
    id: 'MP.L2-3.8.9',
    domain: 'Media Protection',
    domainAbbrev: 'MP',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.8.9',
    title: 'Protect the confidentiality of backup CUI at storage locations.',
  },
  'PS.L2-3.9.1': {
    id: 'PS.L2-3.9.1',
    domain: 'Personnel Security',
    domainAbbrev: 'PS',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.9.1',
    title: 'Screen individuals prior to authorizing access to organizational systems containing CUI.',
  },
  'PS.L2-3.9.2': {
    id: 'PS.L2-3.9.2',
    domain: 'Personnel Security',
    domainAbbrev: 'PS',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.9.2',
    title: 'Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers',
  },
  'PE.L2-3.10.1': {
    id: 'PE.L2-3.10.1',
    domain: 'Physical Protection',
    domainAbbrev: 'PE',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.10.1',
    title: 'Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.',
  },
  'PE.L2-3.10.2': {
    id: 'PE.L2-3.10.2',
    domain: 'Physical Protection',
    domainAbbrev: 'PE',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.10.2',
    title: 'Protect and monitor the physical facility and support infrastructure for organizational systems.',
  },
  'PE.L2-3.10.3': {
    id: 'PE.L2-3.10.3',
    domain: 'Physical Protection',
    domainAbbrev: 'PE',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.10.3',
    title: 'Escort visitors and monitor visitor activity.',
  },
  'PE.L2-3.10.4': {
    id: 'PE.L2-3.10.4',
    domain: 'Physical Protection',
    domainAbbrev: 'PE',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.10.4',
    title: 'Maintain audit logs of physical access.',
  },
  'PE.L2-3.10.5': {
    id: 'PE.L2-3.10.5',
    domain: 'Physical Protection',
    domainAbbrev: 'PE',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.10.5',
    title: 'Control and manage physical access devices.',
  },
  'PE.L2-3.10.6': {
    id: 'PE.L2-3.10.6',
    domain: 'Physical Protection',
    domainAbbrev: 'PE',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.10.6',
    title: 'Enforce safeguarding measures for CUI at alternate work sites.',
  },
  'RA.L2-3.11.1': {
    id: 'RA.L2-3.11.1',
    domain: 'Risk Assessment',
    domainAbbrev: 'RA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.11.1',
    title: 'Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI',
  },
  'RA.L2-3.11.2': {
    id: 'RA.L2-3.11.2',
    domain: 'Risk Assessment',
    domainAbbrev: 'RA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.11.2',
    title: 'Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.',
  },
  'RA.L2-3.11.3': {
    id: 'RA.L2-3.11.3',
    domain: 'Risk Assessment',
    domainAbbrev: 'RA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.11.3',
    title: 'Remediate vulnerabilities in accordance with risk assessments.',
  },
  'CA.L2-3.12.1': {
    id: 'CA.L2-3.12.1',
    domain: 'Security Assessment',
    domainAbbrev: 'CA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.12.1',
    title: 'Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.',
  },
  'CA.L2-3.12.2': {
    id: 'CA.L2-3.12.2',
    domain: 'Security Assessment',
    domainAbbrev: 'CA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.12.2',
    title: 'Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.',
  },
  'CA.L2-3.12.3': {
    id: 'CA.L2-3.12.3',
    domain: 'Security Assessment',
    domainAbbrev: 'CA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.12.3',
    title: 'Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.',
  },
  'CA.L2-3.12.4': {
    id: 'CA.L2-3.12.4',
    domain: 'Security Assessment',
    domainAbbrev: 'CA',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.12.4',
    title: 'Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.[28]',
  },
  'SC.L2-3.13.1': {
    id: 'SC.L2-3.13.1',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.13.1',
    title: 'Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.',
  },
  'SC.L2-3.13.2': {
    id: 'SC.L2-3.13.2',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.13.2',
    title: 'Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.',
  },
  'SC.L2-3.13.3': {
    id: 'SC.L2-3.13.3',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.3',
    title: 'Separate user functionality from system management functionality.',
  },
  'SC.L2-3.13.4': {
    id: 'SC.L2-3.13.4',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.4',
    title: 'Prevent unauthorized and unintended information transfer via shared system resources.',
  },
  'SC.L2-3.13.5': {
    id: 'SC.L2-3.13.5',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.5',
    title: 'Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.',
  },
  'SC.L2-3.13.6': {
    id: 'SC.L2-3.13.6',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.6',
    title: 'Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).',
  },
  'SC.L2-3.13.7': {
    id: 'SC.L2-3.13.7',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.7',
    title: 'Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).',
  },
  'SC.L2-3.13.8': {
    id: 'SC.L2-3.13.8',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.8',
    title: 'Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.',
  },
  'SC.L2-3.13.9': {
    id: 'SC.L2-3.13.9',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.9',
    title: 'Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.',
  },
  'SC.L2-3.13.10': {
    id: 'SC.L2-3.13.10',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.10',
    title: 'Establish and manage cryptographic keys for cryptography employed in organizational systems.',
  },
  'SC.L2-3.13.11': {
    id: 'SC.L2-3.13.11',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.11',
    title: 'Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.',
  },
  'SC.L2-3.13.12': {
    id: 'SC.L2-3.13.12',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.12',
    title: 'Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.[29].',
  },
  'SC.L2-3.13.13': {
    id: 'SC.L2-3.13.13',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.13',
    title: 'Control and monitor the use of mobile code.',
  },
  'SC.L2-3.13.14': {
    id: 'SC.L2-3.13.14',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.14',
    title: 'Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.',
  },
  'SC.L2-3.13.15': {
    id: 'SC.L2-3.13.15',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.15',
    title: 'Protect the authenticity of communications sessions.',
  },
  'SC.L2-3.13.16': {
    id: 'SC.L2-3.13.16',
    domain: 'System and Communications Protection',
    domainAbbrev: 'SC',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.13.16',
    title: 'Protect the confidentiality of CUI at rest.',
  },
  'SI.L2-3.14.1': {
    id: 'SI.L2-3.14.1',
    domain: 'System and Information Integrity',
    domainAbbrev: 'SI',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.14.1',
    title: 'Identify, report, and correct system flaws in a timely manner.',
  },
  'SI.L2-3.14.2': {
    id: 'SI.L2-3.14.2',
    domain: 'System and Information Integrity',
    domainAbbrev: 'SI',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.14.2',
    title: 'Provide protection from malicious code at designated locations within organizational systems.',
  },
  'SI.L2-3.14.3': {
    id: 'SI.L2-3.14.3',
    domain: 'System and Information Integrity',
    domainAbbrev: 'SI',
    level: 2,
    revision: 'rev2',
    requirementKind: 'basic',
    nist800171: '3.14.3',
    title: 'Monitor system security alerts and advisories and take action in response.',
  },
  'SI.L2-3.14.4': {
    id: 'SI.L2-3.14.4',
    domain: 'System and Information Integrity',
    domainAbbrev: 'SI',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.14.4',
    title: 'Update malicious code protection mechanisms when new releases are available.',
  },
  'SI.L2-3.14.5': {
    id: 'SI.L2-3.14.5',
    domain: 'System and Information Integrity',
    domainAbbrev: 'SI',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.14.5',
    title: 'Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.',
  },
  'SI.L2-3.14.6': {
    id: 'SI.L2-3.14.6',
    domain: 'System and Information Integrity',
    domainAbbrev: 'SI',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.14.6',
    title: 'Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.',
  },
  'SI.L2-3.14.7': {
    id: 'SI.L2-3.14.7',
    domain: 'System and Information Integrity',
    domainAbbrev: 'SI',
    level: 2,
    revision: 'rev2',
    requirementKind: 'derived',
    nist800171: '3.14.7',
    title: 'Identify unauthorized use of organizational systems.',
  },
}

/** Total number of CMMC 2.0 Level 2 practices. The denominator for coverage reporting. */
export const CMMC2_PRACTICE_COUNT = 110
