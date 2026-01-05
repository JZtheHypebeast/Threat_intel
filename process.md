flowchart TD
  START([Start]) --> ARGS["Parse CLI args"]
  ARGS --> DEC{Pipeline flags?}

  DEC -- No --> MENU["Interactive menu"]
  MENU --> ROUTE["Dispatch selection"]

  DEC -- Yes --> ROUTE

  %% CVE
  ROUTE -->|cve| CVE1["Fetch KEV + NVD"]
  CVE1 --> CVE2["Normalize & vendor match"]
  CVE2 --> CVE3{LLM enabled?}
  CVE3 -- Yes --> CVE4["LLM refinement"]
  CVE3 -- No --> CVE5["Skip LLM"]
  CVE4 --> CVE6["Write reports"]
  CVE5 --> CVE6

  %% Articles
  ROUTE -->|articles| A1["Fetch RSS"]
  A1 --> A2["Dedupe & rawtext JSON"]
  A2 --> A3{Run LLM?}
  A3 -- Yes --> A4["Enrich → NDJSON + MD"]
  A3 -- No --> A5["Stop"]

  %% PDF
  ROUTE -->|pdf| P1["Extract PDF text"]
  P1 --> P2["Normalize & write NDJSON"]
  P2 --> P3{SIEM enabled?}
  P3 -- Yes --> P4["Send to Elastic"]
  P3 -- No --> END([Done])

  %% Reporting
  ROUTE -->|reporting| R1["Load historical outputs"]
  R1 --> R2["LLM cumulative report"]

  %% Styling
  %% Control
  linkStyle 0,1,2,3,4 stroke:#1f77b4,stroke-width:2px

  %% Data processing
  linkStyle 5,6,7,8,9,10,11 stroke:#2ca02c,stroke-width:2px

  %% Decisions
  linkStyle 12,13,14,15,16 stroke:#ff7f0e,stroke-width:2px

  %% Delivery
  linkStyle 17 stroke:#d62728,stroke-width:2px
