// AWS Cloud Security Auditor - Application Controller

// Mock Templates Database
const templates = {
  "s3-public": `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion"
      ],
      "Resource": "arn:aws:s3:::prod-billing-reports/*"
    }
  ]
}`,
  "iam-wildcard": `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WildcardAdminPrivileges",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "AllowIAMPassRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/AppExecutionRole"
    }
  ]
}`,
  "secgroup-open": `{
  "GroupId": "sg-01f2385b",
  "GroupName": "ssh-access-sg",
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 22,
      "ToPort": 22,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0",
          "Description": "Allow SSH from anywhere"
        }
      ]
    },
    {
      "IpProtocol": "tcp",
      "FromPort": 80,
      "ToPort": 80,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0",
          "Description": "Allow HTTP web traffic"
        }
      ]
    }
  ]
}`,
  "kms-safe": `{
  "Version": "2012-10-17",
  "Id": "kms-key-policy",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow Key Usage",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/AppCryptRole"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}`
};

// Application State Management
let currentTab = 'dashboard';
let scanRunning = false;

document.addEventListener('DOMContentLoaded', () => {
  // Navigation
  initNavigation();

  // Accordions (Checklist + Findings)
  initAccordions();

  // Policy Analyzer Init
  initAnalyzer();

  // Scanner Simulator Init
  initScanner();

  // Policy Generator Init
  initGenerator();
});

// View Navigation Logic
function initNavigation() {
  const navBtns = document.querySelectorAll('.nav-btn');
  const viewTitles = {
    'dashboard': { title: 'Dashboard', desc: 'Security posture summary and analysis history' },
    'analyzer': { title: 'IAM Policy & Config Analyzer', desc: 'Paste AWS configurations to check for access vulnerabilities' },
    'scanner': { title: 'Compliance Scan Simulator', desc: 'Run automated audit scans against simulated cloud nodes' },
    'compliance': { title: 'CIS Checklist Control Panel', desc: 'Track compliance status against CIS AWS Foundations Benchmarks' },
    'generator': { title: 'IAM Policy Generator', desc: 'Create secure-by-design AWS policies under Least Privilege rules' }
  };

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      switchToTab(tabId);
    });
  });
}

function switchToTab(tabId) {
  const navBtns = document.querySelectorAll('.nav-btn');
  const panels = document.querySelectorAll('.tab-panel');
  const titleEl = document.getElementById('current-view-title');
  const descEl = document.getElementById('current-view-desc');
  const viewTitles = {
    'dashboard': { title: 'Dashboard', desc: 'Security posture summary and analysis history' },
    'analyzer': { title: 'IAM Policy & Config Analyzer', desc: 'Paste AWS configurations to check for access vulnerabilities' },
    'scanner': { title: 'Compliance Scan Simulator', desc: 'Run automated audit scans against simulated cloud nodes' },
    'compliance': { title: 'CIS Checklist Control Panel', desc: 'Track compliance status against CIS AWS Foundations Benchmarks' },
    'generator': { title: 'IAM Policy Generator', desc: 'Create secure-by-design AWS policies under Least Privilege rules' }
  };

  navBtns.forEach(b => b.classList.remove('active'));
  panels.forEach(p => p.classList.remove('active'));

  // Set active class
  const targetBtn = document.querySelector(`[data-tab="${tabId}"]`);
  const targetPanel = document.getElementById(`panel-${tabId}`);
  if (targetBtn) targetBtn.classList.add('active');
  if (targetPanel) targetPanel.classList.add('active');

  // Update Headers
  if (viewTitles[tabId]) {
    titleEl.textContent = viewTitles[tabId].title;
    descEl.textContent = viewTitles[tabId].desc;
  }

  currentTab = tabId;
}

// Global Accordions helper
function initAccordions() {
  document.addEventListener('click', (e) => {
    // CIS checklist accordion
    const accordionTitle = e.target.closest('.accordion-title');
    if (accordionTitle) {
      const item = accordionTitle.closest('.accordion-item');
      item.classList.toggle('expanded');
    }
  });

  // CIS Checklist filters
  const filterChips = document.querySelectorAll('.filter-chip');
  filterChips.forEach(chip => {
    chip.addEventListener('click', () => {
      filterChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');

      const filterType = chip.getAttribute('data-filter');
      const checklistItems = document.querySelectorAll('.checklist-item');

      checklistItems.forEach(item => {
        const itemStatus = item.getAttribute('data-status');
        if (filterType === 'all') {
          item.style.display = 'flex';
        } else if (filterType === 'pass' && itemStatus === 'pass') {
          item.style.display = 'flex';
        } else if (filterType === 'fail' && itemStatus === 'fail') {
          item.style.display = 'flex';
        } else {
          item.style.display = 'none';
        }
      });
    });
  });
}

// IAM Policy & Config Analyzer Logic
function initAnalyzer() {
  const templateSelect = document.getElementById('policy-template-select');
  const policyTextArea = document.getElementById('policy-textarea');
  const analyzeBtn = document.getElementById('analyze-policy-btn');
  const clearBtn = document.getElementById('clear-policy-btn');
  const placeholderEl = document.getElementById('results-placeholder');
  const contentEl = document.getElementById('results-content-area');
  const findingsList = document.getElementById('findings-list-container');
  const healthVal = document.getElementById('results-health-val');
  const pillCrit = document.getElementById('pill-crit');
  const pillHigh = document.getElementById('pill-high');
  const pillMed = document.getElementById('pill-med');

  // Template select trigger
  templateSelect.addEventListener('change', () => {
    const selectedTemplate = templateSelect.value;
    if (templates[selectedTemplate]) {
      policyTextArea.value = templates[selectedTemplate];
      updateLineNumbers();
    }
  });

  // TextArea line numbering
  policyTextArea.addEventListener('input', updateLineNumbers);
  policyTextArea.addEventListener('scroll', () => {
    document.getElementById('editor-line-numbers').scrollTop = policyTextArea.scrollTop;
  });

  clearBtn.addEventListener('click', () => {
    policyTextArea.value = '';
    templateSelect.value = '';
    updateLineNumbers();
    placeholderEl.classList.remove('hidden');
    contentEl.classList.add('hidden');
  });

  analyzeBtn.addEventListener('click', () => {
    const content = policyTextArea.value.trim();
    if (!content) {
      alert('Please paste some JSON configuration first.');
      return;
    }

    try {
      const parsed = JSON.parse(content);
      runPolicyAnalysis(parsed);
    } catch (err) {
      alert(`Invalid JSON format: ${err.message}`);
    }
  });
}

function updateLineNumbers() {
  const textarea = document.getElementById('policy-textarea');
  const lineNumbers = document.getElementById('editor-line-numbers');
  const lines = textarea.value.split('\n');
  const count = Math.max(lines.length, 1);
  
  let numbersHtml = '';
  for (let i = 1; i <= count; i++) {
    numbersHtml += `<span>${i}</span>`;
  }
  lineNumbers.innerHTML = numbersHtml;
}

// Policy Analyzer Rule Checks
function runPolicyAnalysis(jsonObj) {
  const placeholderEl = document.getElementById('results-placeholder');
  const contentEl = document.getElementById('results-content-area');
  const findingsList = document.getElementById('findings-list-container');
  const healthVal = document.getElementById('results-health-val');
  const pillCrit = document.getElementById('pill-crit');
  const pillHigh = document.getElementById('pill-high');
  const pillMed = document.getElementById('pill-med');

  findingsList.innerHTML = ''; // reset findings
  let findings = [];
  let scorePoints = 100;

  // Let's analyze if S3 or IAM based
  if (jsonObj.Statement && Array.isArray(jsonObj.Statement)) {
    // Loop statements
    jsonObj.Statement.forEach((stmt, index) => {
      const effect = stmt.Effect;
      const principal = stmt.Principal;
      const action = stmt.Action;
      const resource = stmt.Resource;
      const condition = stmt.Condition;

      const sid = stmt.Sid || `Statement #${index + 1}`;

      // Check 1: S3 Public Access Check
      if (effect === 'Allow' && (principal === '*' || (principal && principal.AWS === '*'))) {
        findings.push({
          severity: 'critical',
          title: `Public Access Granted via Statement: "${sid}"`,
          desc: `The policy grants public (anonymous) operations to actions. This allows anybody on the internet to operate on your resources.`,
          remediation: `Restructure Principal to limit access to approved IAM user/role ARNs or VPC IP conditions:
"Principal": {
  "AWS": "arn:aws:iam::123456789012:role/SecureAppRole"
}`
        });
        scorePoints -= 40;
      }

      // Check 2: IAM Wildcard Admin Check
      const hasWildcardAction = action === '*' || (Array.isArray(action) && action.includes('*'));
      const hasWildcardResource = resource === '*' || (Array.isArray(resource) && resource.includes('*'));

      if (effect === 'Allow' && hasWildcardAction && hasWildcardResource) {
        findings.push({
          severity: 'critical',
          title: `Broad Administrator Access: "${sid}"`,
          desc: `Granting "*" actions on "*" resources gives full administrative permissions. This overrides boundaries and violates the Principal of Least Privilege.`,
          remediation: `Break down user permissions into specific actions and limit resource scopes:
"Action": [
  "s3:GetObject",
  "s3:PutObject"
],
"Resource": "arn:aws:s3:::my-production-assets-bucket/*"`
        });
        scorePoints -= 50;
      } else if (effect === 'Allow' && hasWildcardAction) {
        // Broad actions but specific resource
        findings.push({
          severity: 'high',
          title: `Overprivileged Wildcard Action: "${sid}"`,
          desc: `Allowing "*" actions grants administrative control over the selected resources. It's recommended to restrict actions to read/write specific parameters.`,
          remediation: `Restructure actions to limit administrative power:
"Action": [
  "dynamodb:GetItem",
  "dynamodb:PutItem"
]`
        });
        scorePoints -= 25;
      }

      // Check 3: KMS key security Check
      if (action && (action === 'kms:*' || (Array.isArray(action) && action.includes('kms:*')))) {
        if (!condition) {
          findings.push({
            severity: 'medium',
            title: `KMS Admin without Condition constraints`,
            desc: `Statement "${sid}" allows full kms actions without enforcing additional contexts such as Multi-Factor Authentication (MFA) or Ip Address checks.`,
            remediation: `Add a condition validation helper inside the block:
"Condition": {
  "Bool": { "aws:MultiFactorAuthPresent": "true" }
}`
          });
          scorePoints -= 15;
        }
      }
    });
  } else if (jsonObj.IpPermissions && Array.isArray(jsonObj.IpPermissions)) {
    // Security Group Analysis
    jsonObj.IpPermissions.forEach(perm => {
      const fromPort = perm.FromPort;
      const toPort = perm.ToPort;
      const ranges = perm.IpRanges || [];

      const isOpenToAll = ranges.some(r => r.CidrIp === '0.0.0.0/0');

      if (isOpenToAll) {
        if (fromPort <= 22 && toPort >= 22) {
          findings.push({
            severity: 'critical',
            title: `SSH Port (22) open to Public Internet`,
            desc: `Security Group ingress rule allows port 22 incoming requests from all addresses (0.0.0.0/0). This exposes your instances to potential brute-force and exploit attempts.`,
            remediation: `Terraform fix:
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["203.0.113.50/32"] # Admin office IP
  security_group_id = aws_security_group.my_sg.id
}`
          });
          scorePoints -= 40;
        } else if (fromPort <= 3389 && toPort >= 3389) {
          findings.push({
            severity: 'critical',
            title: `RDP Port (3389) open to Public Internet`,
            desc: `Windows Remote Desktop Protocol port 3389 is exposed to the public internet, posing high risk of credential harvesting.`,
            remediation: `Restrict security group rules to known office CIDR ranges or require a corporate Client VPN for access.`
          });
          scorePoints -= 45;
        } else if (fromPort === 80 || fromPort === 443) {
          findings.push({
            severity: 'medium',
            title: `Public Port Exposure (HTTP/HTTPS)`,
            desc: `Ports 80/443 are open to 0.0.0.0/0. If this is a load balancer or web server, this is normal. Otherwise, it should be restricted to CDN subnet ranges.`,
            remediation: `Confirm if public load balancing is necessary, otherwise limit access via AWS WAF or CloudFront security rules.`
          });
          scorePoints -= 5;
        }
      }
    });
  }

  // Fallback if no specific issues matched, but we parsed valid JSON
  if (findings.length === 0) {
    findings.push({
      severity: 'success',
      title: `No Vulnerabilities Detected`,
      desc: `Configuration parsed successfully and checks passed! We did not identify any broad wildcards, public exposures, or unconstrained accesses.`,
      remediation: `Maintain regular reviews and implement policy validations in your CI/CD pipelines.`
    });
  }

  // Calculate Health & Grade
  scorePoints = Math.max(scorePoints, 10);
  let gradeText = 'Grade F';
  let colorClass = 'text-danger';

  if (scorePoints >= 95) { gradeText = 'Grade A+'; colorClass = 'text-success'; }
  else if (scorePoints >= 90) { gradeText = 'Grade A-'; colorClass = 'text-success'; }
  else if (scorePoints >= 80) { gradeText = 'Grade B'; colorClass = 'text-warning'; }
  else if (scorePoints >= 70) { gradeText = 'Grade C'; colorClass = 'text-warning'; }
  else if (scorePoints >= 50) { gradeText = 'Grade D'; colorClass = 'text-danger'; }

  healthVal.className = `health-val ${colorClass}`;
  healthVal.textContent = `${scorePoints}% (${gradeText})`;

  // Count types
  const critCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const medCount = findings.filter(f => f.severity === 'medium').length;

  pillCrit.textContent = `${critCount} Critical`;
  pillHigh.textContent = `${highCount} High`;
  pillMed.textContent = `${medCount} Med`;

  // Draw entries
  findings.forEach((finding, idx) => {
    const cardDiv = document.createElement('div');
    cardDiv.className = `finding-entry`;
    cardDiv.innerHTML = `
      <div class="finding-trigger" data-index="${idx}">
        <div class="trigger-left">
          <span class="finding-indicator ${finding.severity}"></span>
          <span class="finding-title">${finding.title}</span>
        </div>
        <svg class="trigger-chevron" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </div>
      <div class="finding-body">
        <p class="finding-desc">${finding.desc}</p>
        ${finding.remediation ? `
          <div class="remediation-drawer">
            <div class="drawer-header">
              <span>Remediation Fix</span>
              <button class="action-btn-small copy-drawer-btn" style="padding: 2px 8px;">Copy</button>
            </div>
            <div class="drawer-content">
              <pre><code>${finding.remediation}</code></pre>
            </div>
          </div>
        ` : ''}
      </div>
    `;

    findingsList.appendChild(cardDiv);
  });

  // Attach dynamic clicks to the newly drawn findings list
  const triggers = findingsList.querySelectorAll('.finding-trigger');
  triggers.forEach(trig => {
    trig.addEventListener('click', () => {
      const entry = trig.closest('.finding-entry');
      entry.classList.toggle('expanded');
    });
  });

  // Attach copy events inside finding drawers
  const copyBtns = findingsList.querySelectorAll('.copy-drawer-btn');
  copyBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const codeBlock = btn.closest('.remediation-drawer').querySelector('code');
      navigator.clipboard.writeText(codeBlock.innerText).then(() => {
        const origText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = origText, 2000);
      });
    });
  });

  // Show results pane
  placeholderEl.classList.add('hidden');
  contentEl.classList.remove('hidden');
}

// SCANNER SIMULATION ENGINE
function initScanner() {
  const startBtn = document.getElementById('start-scan-btn');
  const consoleEl = document.getElementById('terminal-console');
  const resultsContainer = document.getElementById('scan-summary-container');
  const findingsGroupEl = document.getElementById('scan-group-findings');

  startBtn.addEventListener('click', () => {
    if (scanRunning) return;
    scanRunning = true;
    startBtn.disabled = true;
    startBtn.innerHTML = `
      <svg class="progress-ring-bar" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" style="animation: pulse 1s infinite;">
        <circle cx="12" cy="12" r="10" />
      </svg>
      Auditing In Progress...
    `;

    resultsContainer.classList.add('hidden');
    consoleEl.innerHTML = `<div class="terminal-line system-line">[INF] Initializing CloudShield Audit Agent...</div>`;
    
    const selectedServices = [];
    if (document.getElementById('scan-iam').checked) selectedServices.push('IAM');
    if (document.getElementById('scan-s3').checked) selectedServices.push('S3');
    if (document.getElementById('scan-network').checked) selectedServices.push('Network');
    if (document.getElementById('scan-kms').checked) selectedServices.push('KMS');
    if (document.getElementById('scan-cloudtrail').checked) selectedServices.push('CloudTrail');

    const baselineVal = document.querySelector('input[name="compliance-baseline"]:checked').value;
    const baselineNames = {
      'cis': 'CIS AWS Foundations Benchmark v1.4.0',
      'soc2': 'SOC 2 Type II Compliance Framework',
      'hipaa': 'HIPAA Security Controls v164'
    };

    const logs = generateAuditLogs(selectedServices, baselineNames[baselineVal]);
    let logIndex = 0;

    function printNextLog() {
      if (logIndex < logs.length) {
        const log = logs[logIndex];
        const lineDiv = document.createElement('div');
        
        let typeClass = 'info-line';
        if (log.type === 'WARN') typeClass = 'warning-line';
        if (log.type === 'DANGER') typeClass = 'danger-line';
        if (log.type === 'SYS') typeClass = 'system-line';

        lineDiv.className = `terminal-line ${typeClass}`;
        lineDiv.innerHTML = log.text;
        
        // Remove old cursor line if exists
        const cursorLine = consoleEl.querySelector('.terminal-prompt').parentNode;
        consoleEl.removeChild(cursorLine);
        
        consoleEl.appendChild(lineDiv);
        
        // Add back cursor prompt
        const promptLine = document.createElement('div');
        promptLine.className = 'terminal-line';
        promptLine.innerHTML = `<span class="terminal-prompt">cloudshield-agent$</span> <span class="cursor"></span>`;
        consoleEl.appendChild(promptLine);
        
        consoleEl.scrollTop = consoleEl.scrollHeight;
        
        logIndex++;
        // Speed control
        setTimeout(printNextLog, Math.random() * 200 + 100);
      } else {
        // Finished Scan
        scanRunning = false;
        startBtn.disabled = false;
        startBtn.innerHTML = `
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>
          Launch Security Scan
        `;
        
        displayScanResults(selectedServices, baselineVal);
      }
    }

    setTimeout(printNextLog, 400);
  });
}

function generateAuditLogs(services, baselineName) {
  let logs = [
    { type: 'SYS', text: `[SYSTEM] Authenticating connection details using AWS Security Token Service (STS)...` },
    { type: 'SYS', text: `[SYSTEM] Successfully established STS credentials. Role assumed: CloudShieldAuditorRole.` },
    { type: 'SYS', text: `[INFO] Targeting compliance framework verification: ${baselineName}` },
    { type: 'INFO', text: `[INFO] Gathering list of active resource profiles...` }
  ];

  services.forEach(svc => {
    if (svc === 'IAM') {
      logs.push(
        { type: 'INFO', text: `[INFO] [IAM] Querying IAM policy lists and access key rotation schedules...` },
        { type: 'WARN', text: `[WARN] [IAM] User 'admin-ci' console access has not rotated password in 180 days.` },
        { type: 'DANGER', text: `[DANGER] [IAM] Managed policy 'custom-admin-helper' contains broad administrator wildcard rules.` },
        { type: 'WARN', text: `[WARN] [IAM] 3 administrator level accounts detected lacking MFA credentials.` }
      );
    }
    if (svc === 'S3') {
      logs.push(
        { type: 'INFO', text: `[INFO] [S3] Querying Amazon Simple Storage Service bucket configuration schemas...` },
        { type: 'DANGER', text: `[DANGER] [S3] Bucket 'prod-billing-reports' is currently flagged as having Public Anonymous access!` },
        { type: 'WARN', text: `[WARN] [S3] Bucket 'staging-logs' does not have default AES-256 S3 bucket encryption enabled.` },
        { type: 'INFO', text: `[INFO] [S3] Verified 11 remaining S3 buckets are encrypted and public blocks are enabled.` }
      );
    }
    if (svc === 'Network') {
      logs.push(
        { type: 'INFO', text: `[INFO] [VPC] Analysing Virtual Private Cloud Security Group rule definitions...` },
        { type: 'DANGER', text: `[DANGER] [VPC] Security Group 'sg-01f2385b' (ssh-access-sg) has SSH port (22) exposed to 0.0.0.0/0!` },
        { type: 'INFO', text: `[INFO] [VPC] Security Group 'sg-09bbcf50' has web HTTP rules open, which matches public load balancing protocols.` }
      );
    }
    if (svc === 'KMS') {
      logs.push(
        { type: 'INFO', text: `[INFO] [KMS] Crawling Customer Managed Keys and policy conditions...` },
        { type: 'INFO', text: `[INFO] [KMS] Key ID: a8f-89bc verified. Managed rotation schedule is active.` }
      );
    }
    if (svc === 'CloudTrail') {
      logs.push(
        { type: 'INFO', text: `[INFO] [CloudTrail] Auditing configuration paths and trail log integrity values...` },
        { type: 'INFO', text: `[INFO] [CloudTrail] Log verification digest keys matched. Trail active in all regions.` }
      );
    }
  });

  logs.push(
    { type: 'SYS', text: `[SYSTEM] Processing collected findings and aggregating results...` },
    { type: 'SYS', text: `[SYSTEM] Cloud Audit Completed successfully.` }
  );

  return logs;
}

function displayScanResults(services, baselineType) {
  const resultsContainer = document.getElementById('scan-summary-container');
  const passVal = document.getElementById('scan-pass-val');
  const failVal = document.getElementById('scan-fail-val');
  const warnVal = document.getElementById('scan-warn-val');
  const scoreVal = document.getElementById('scan-score-val');
  const findingsGroupEl = document.getElementById('scan-group-findings');

  let passed = 0;
  let failed = 0;
  let manual = 0;

  findingsGroupEl.innerHTML = ''; // Clear results

  services.forEach(svc => {
    const serviceGroup = document.createElement('div');
    serviceGroup.className = 'scan-service-group';

    let headerSvg = '';
    let bodyHtml = '';

    if (svc === 'IAM') {
      passed += 2; failed += 2; manual += 1;
      headerSvg = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`;
      bodyHtml = `
        <div class="checklist-item checked-fail" data-status="fail">
          <span class="checklist-bullet"></span>
          <div class="checklist-info">
            <h5>Broad Administrator Access</h5>
            <p>IAM Policy <code>custom-admin-helper</code> grants <code>*:*</code> actions on all resources.</p>
          </div>
          <span class="status-badge fail">Failed</span>
        </div>
        <div class="checklist-item checked-fail" data-status="fail">
          <span class="checklist-bullet"></span>
          <div class="checklist-info">
            <h5>MFA Configuration Missing</h5>
            <p>3 root-level administrators do not have Multi-Factor Authentication configured.</p>
          </div>
          <span class="status-badge fail">Failed</span>
        </div>
        <div class="checklist-item checked-pass" data-status="pass">
          <span class="checklist-bullet"></span>
          <div class="checklist-info">
            <h5>Access Key Expiration</h5>
            <p>Active keys are rotated inside the 90 days secure timeline compliance limit.</p>
          </div>
          <span class="status-badge pass">Passed</span>
        </div>
      `;
    }
    if (svc === 'S3') {
      passed += 11; failed += 2;
      headerSvg = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`;
      bodyHtml = `
        <div class="checklist-item checked-fail" data-status="fail">
          <span class="checklist-bullet"></span>
          <div class="checklist-info">
            <h5>S3 Public Anonymous Access Open</h5>
            <p>Anonymous read permissions active on production billing assets storage <code>prod-billing-reports</code>.</p>
          </div>
          <span class="status-badge fail">Failed</span>
        </div>
        <div class="checklist-item checked-fail" data-status="fail">
          <span class="checklist-bullet"></span>
          <div class="checklist-info">
            <h5>S3 Default Encryption Disabled</h5>
            <p>S3 bucket <code>staging-logs</code> has no KMS/SSE server side encryption default configs.</p>
          </div>
          <span class="status-badge fail">Failed</span>
        </div>
      `;
    }
    if (svc === 'Network') {
      passed += 3; failed += 1;
      headerSvg = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/></svg>`;
      bodyHtml = `
        <div class="checklist-item checked-fail" data-status="fail">
          <span class="checklist-bullet"></span>
          <div class="checklist-info">
            <h5>SSH Open to Internet</h5>
            <p>Security group <code>sg-01f2385b</code> allows TCP port 22 incoming requests from all addresses (0.0.0.0/0).</p>
          </div>
          <span class="status-badge fail">Failed</span>
        </div>
      `;
    }
    if (svc === 'KMS') {
      passed += 4;
      headerSvg = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
      bodyHtml = `
        <div class="checklist-item checked-pass" data-status="pass">
          <span class="checklist-bullet"></span>
          <div class="checklist-info">
            <h5>KMS CMK Rotation Active</h5>
            <p>Verified annual rotation is configured on all customer managed encryption keys.</p>
          </div>
          <span class="status-badge pass">Passed</span>
        </div>
      `;
    }
    if (svc === 'CloudTrail') {
      passed += 2;
      headerSvg = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`;
      bodyHtml = `
        <div class="checklist-item checked-pass" data-status="pass">
          <span class="checklist-bullet"></span>
          <div class="checklist-info">
            <h5>CloudTrail Active globally</h5>
            <p>Validated trails are recording write operations across all active geographic sub-regions.</p>
          </div>
          <span class="status-badge pass">Passed</span>
        </div>
      `;
    }

    serviceGroup.innerHTML = `
      <div class="scan-service-header">
        ${headerSvg}
        <span>AWS ${svc} Audit Checks</span>
      </div>
      <div class="scan-service-body">
        ${bodyHtml}
      </div>
    `;

    findingsGroupEl.appendChild(serviceGroup);
  });

  const total = passed + failed;
  const score = total > 0 ? Math.round((passed / total) * 100) : 100;

  // Set counters
  passVal.textContent = passed;
  failVal.textContent = failed;
  warnVal.textContent = manual;
  scoreVal.textContent = `${score}%`;

  resultsContainer.classList.remove('hidden');

  // Trigger Dashboard Score Update to reflect scanned scores
  updateDashboardScores(score, failed);
}

function updateDashboardScores(score, failedCount) {
  const scorePercent = document.getElementById('score-percent-val');
  const scoreGrade = document.getElementById('score-grade-val');
  const scoreRing = document.getElementById('score-ring');
  
  // Calculate grade
  let gradeText = 'Grade F';
  let color = '#ff4757'; // red
  if (score >= 90) { gradeText = 'Grade A'; color = '#2ed573'; }
  else if (score >= 80) { gradeText = 'Grade B'; color = '#ffa502'; }
  else if (score >= 70) { gradeText = 'Grade C'; color = '#ffa502'; }
  else if (score >= 50) { gradeText = 'Grade D'; color = '#ff4757'; }

  scorePercent.textContent = `${score}%`;
  scoreGrade.textContent = gradeText;

  // Circle animation offset calculation: radius is 70, stroke dash is 2 * PI * r = 439.82
  const maxDash = 439.82;
  const offset = maxDash - (score / 100) * maxDash;
  scoreRing.style.strokeDashoffset = offset;
  scoreRing.style.stroke = color;

  // Update dynamic count dashboard summaries
  document.getElementById('stat-crit-count').textContent = Math.round(failedCount * 0.4);
  document.getElementById('stat-high-count').textContent = Math.round(failedCount * 0.6);

  // Update global compliance ratings
  document.getElementById('comp-cis-val').textContent = `${score}%`;
  document.getElementById('comp-cis-fill').style.width = `${score}%`;
  if (score >= 80) {
    document.getElementById('comp-cis-fill').className = 'comp-fill success';
  } else if (score >= 60) {
    document.getElementById('comp-cis-fill').className = 'comp-fill warning';
  } else {
    document.getElementById('comp-cis-fill').className = 'comp-fill danger';
  }
}

// POLICY GENERATOR LOGIC
function initGenerator() {
  const nameInput = document.getElementById('gen-policy-name');
  const serviceSelect = document.getElementById('gen-service');
  const actionRadios = document.querySelectorAll('input[name="gen-action-level"]');
  const resourceInput = document.getElementById('gen-resource');
  const mfaCheckbox = document.getElementById('gen-mfa');
  const transportCheckbox = document.getElementById('gen-secure-transport');
  const outputEl = document.getElementById('generated-json-code');
  const copyBtn = document.getElementById('copy-gen-policy-btn');

  // Attach change event listeners to all form controls
  const updatePolicy = () => {
    const policyJson = buildPolicyJSON({
      name: nameInput.value.trim() || 'CustomSecurePolicy',
      service: serviceSelect.value,
      actionsLevel: document.querySelector('input[name="gen-action-level"]:checked').value,
      resource: resourceInput.value.trim() || '*',
      requireMFA: mfaCheckbox.checked,
      requireHTTPS: transportCheckbox.checked
    });
    outputEl.textContent = policyJson;
  };

  nameInput.addEventListener('input', updatePolicy);
  serviceSelect.addEventListener('change', updatePolicy);
  actionRadios.forEach(rad => rad.addEventListener('change', updatePolicy));
  resourceInput.addEventListener('input', updatePolicy);
  mfaCheckbox.addEventListener('change', updatePolicy);
  transportCheckbox.addEventListener('change', updatePolicy);

  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(outputEl.textContent).then(() => {
      const origText = copyBtn.innerHTML;
      copyBtn.textContent = 'Copied!';
      setTimeout(() => copyBtn.innerHTML = origText, 2000);
    });
  });

  // Run first initialization
  updatePolicy();
}

function buildPolicyJSON(config) {
  const serviceActions = {
    s3: {
      read: ["s3:GetObject", "s3:ListBucket", "s3:GetObjectVersion"],
      write: ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
      readwrite: ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"],
      admin: ["s3:*"]
    },
    kms: {
      read: ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListKeys"],
      write: ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
      readwrite: ["kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
      admin: ["kms:*"]
    },
    dynamodb: {
      read: ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan"],
      write: ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
      readwrite: ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
      admin: ["dynamodb:*"]
    },
    sqs: {
      read: ["sqs:ReceiveMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"],
      write: ["sqs:SendMessage", "sqs:DeleteMessage", "sqs:PurgeQueue"],
      readwrite: ["sqs:ReceiveMessage", "sqs:SendMessage", "sqs:DeleteMessage", "sqs:GetQueueUrl"],
      admin: ["sqs:*"]
    }
  };

  const selectedActions = serviceActions[config.service][config.actionsLevel];
  
  const policy = {
    Version: "2012-10-17",
    Statement: []
  };

  // Main Access Statement
  const statement = {
    Sid: `${config.name}MainAccess`,
    Effect: "Allow",
    Action: selectedActions,
    Resource: config.resource
  };

  // Require MFA condition
  if (config.requireMFA) {
    statement.Condition = {
      Bool: {
        "aws:MultiFactorAuthPresent": "true"
      }
    };
  }

  policy.Statement.push(statement);

  // HTTPS Transport check (requires a DENY block on S3 specifically)
  if (config.requireHTTPS && config.service === 's3') {
    // Determine bucket root ARN from object resource ARN (e.g. arn:aws:s3:::bucket/* -> arn:aws:s3:::bucket)
    let bucketArn = config.resource;
    if (bucketArn.endsWith('/*')) {
      bucketArn = bucketArn.substring(0, bucketArn.length - 2);
    }

    policy.Statement.push({
      Sid: "EnforceSecureTransport",
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: [
        bucketArn,
        `${bucketArn}/*`
      ],
      Condition: {
        Bool: {
          "aws:SecureTransport": "false"
        }
      }
    });
  } else if (config.requireHTTPS) {
    // For general non-s3 services, we append secure transport check
    if (!statement.Condition) {
      statement.Condition = {};
    }
    statement.Condition.Bool = statement.Condition.Bool || {};
    statement.Condition.Bool["aws:SecureTransport"] = "true";
  }

  return JSON.stringify(policy, null, 2);
}
