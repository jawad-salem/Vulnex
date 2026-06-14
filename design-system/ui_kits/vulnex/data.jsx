// Demo data — mirrors the Vulnex seed_demo fixture (Acme Corp, 2 engagements, 8 findings).
window.VULNEX_DATA = {
  engagements: [
    {
      id: 'red', name: 'Acme Corp — Red Team Adversary Simulation', client: 'Acme Corp',
      type: 'Red team', status: 'exploitation', statusLabel: 'Exploitation',
      phase: 3, findingCount: 5, lead: 'Dana Okoye',
      window: 'Jun 2 – Jun 24, 2026',
      scope: ['*.acme.example', 'dc01.internal.acme.example', '10.10.0.0/16'],
    },
    {
      id: 'ext', name: 'Acme Corp — Q2 External Pentest', client: 'Acme Corp',
      type: 'External', status: 'reporting', statusLabel: 'Reporting',
      phase: 4, findingCount: 3, lead: 'Dana Okoye',
      window: 'May 12 – May 30, 2026',
      scope: ['app.acme.example', 'api.acme.example'],
    },
  ],
  findings: [
    { id:'f1', eng:'red', title:'Kerberoastable service account with weak password', host:'dc01.internal.acme.example', port:88, severity:'critical', sevLabel:'Critical', cvss:9.1, status:'open', statusLabel:'Open', review:'in_review', reviewLabel:'In review', assignee:'Dana Okoye', due:'Jun 24', sla:'on_track', date:'Jun 10, 2026' },
    { id:'f2', eng:'red', title:'Unconstrained delegation on legacy host', host:'srv-print01.acme.example', port:445, severity:'high', sevLabel:'High', cvss:8.1, status:'confirmed', statusLabel:'Confirmed', review:'approved', reviewLabel:'Approved', assignee:'Dana Okoye', due:'Jun 28', sla:'on_track', date:'Jun 9, 2026' },
    { id:'f3', eng:'red', title:'LLMNR/NBT-NS poisoning yields NetNTLMv2 hashes', host:'10.10.4.0/24', port:null, severity:'high', sevLabel:'High', cvss:7.4, status:'open', statusLabel:'Open', review:'draft', reviewLabel:'Draft', assignee:null, due:'Jun 26', sla:'due_soon', date:'Jun 8, 2026' },
    { id:'f4', eng:'red', title:'Shared local admin password across workstations', host:'10.10.12.0/24', port:null, severity:'medium', sevLabel:'Medium', cvss:6.5, status:'confirmed', statusLabel:'Confirmed', review:'in_review', reviewLabel:'In review', assignee:'Dana Okoye', due:'Jul 2', sla:'on_track', date:'Jun 7, 2026' },
    { id:'f5', eng:'red', title:'Verbose SMB signing disabled', host:'fs01.acme.example', port:445, severity:'low', sevLabel:'Low', cvss:3.7, status:'accepted', statusLabel:'Accepted', review:'approved', reviewLabel:'Approved', assignee:'Dana Okoye', due:null, sla:'closed', date:'Jun 6, 2026' },
    { id:'f6', eng:'ext', title:'SQL injection in invoice search parameter', host:'app.acme.example', port:443, severity:'critical', sevLabel:'Critical', cvss:9.8, status:'remediated', statusLabel:'Remediated', review:'approved', reviewLabel:'Approved', assignee:'Dana Okoye', due:null, sla:'closed', date:'May 18, 2026' },
    { id:'f7', eng:'ext', title:'Stored XSS in support ticket subject', host:'app.acme.example', port:443, severity:'high', sevLabel:'High', cvss:7.2, status:'confirmed', statusLabel:'Confirmed', review:'approved', reviewLabel:'Approved', assignee:'Dana Okoye', due:'May 30', sla:'on_track', date:'May 16, 2026' },
    { id:'f8', eng:'ext', title:'Missing rate-limit on password reset endpoint', host:'api.acme.example', port:443, severity:'medium', sevLabel:'Medium', cvss:5.3, status:'open', statusLabel:'Open', review:'in_review', reviewLabel:'In review', assignee:null, due:'May 30', sla:'overdue', date:'May 15, 2026' },
  ],
};
