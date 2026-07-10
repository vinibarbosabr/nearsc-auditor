This is a vulnerability classification table for smart contracts (v2.0), by HackenProof.

Source: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/smart-contracts

This table outlines how we categorize smart contract vulnerabilities by severity. Classifications are based on financial loss, disruption of core functionality, or manipulation of contract outcomes in live systems.

**Severity**

**Example Vulnerabilities**

🔴 **Critical**

- **Direct theft of funds or NFTs**
- **Permanent freezing of funds or NFTs**
- **Governance result manipulation** (e.g., vote hijacking, quorum bypass)
- **Protocol insolvency** (e.g., under-collateralization, unbacked tokens, critical mispricing)
- **Unauthorized Minting / Burning of Tokens**: If not covered, include direct manipulation of token supply.

🟠 **High**

- **Temporary freezing of funds or NFTs**
- **Theft of unclaimed funds** (e.g., yield, royalties)
- **Permanent freezing of unclaimed funds
- **Oracle Manipulation** (High): Influencing on-chain price feeds or data sources.

🟡 **Medium**

- **Theft of gas** (unbounded loops, expensive operations exploitable by attackers)
- **Gas limit / Out-of-Gas vulnerabilities**: Poor gas handling leading to transaction failure, loss of funds, or halted functionality
- **Denial of Service (DoS)**: Gas exhaustion, block stuffing, or malicious state manipulation that disrupts contract availability
- **No-profit attacks (Griefing)**: Attacks that damage the protocol or users without financial gain for the attacker

🟢 **Low**

- **Failure to deliver promised returns** (e.g., staking pool advertises fixed APY but underperforms due to bugs or flawed logic)
- **Uninitialized Storage Variables**: Can lead to privilege escalation but often low-risk.

If the issue is not under one of the mentioned vulnerabilities, we use the [Common Vulnerability Scoring System](https://www.first.org/cvss/user-guide) to assess the severity of your vulnerability.

**Disclaimer:** Any **privileged** actions may be considered grounds for a severity downgrade or vulnerability disqualification.