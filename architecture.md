flowchart TB
  %% ===== Nodes =====
  MAIN["main.py\nCLI + Orchestration"]

  CONFIG["config.py\nEnv, paths, flags"]
  PROG["progress.py\nProgress animation"]

  CVE["CVE.py\nStructured CVE pipeline"]
  ART["articles.py\nRSS / rawtext"]
  PDF["pdf.py\nPDF ingestion"]
  GEO["geofeed.py\nGeoFeed scanning"]
  REP["reporting.py\nMulti-day reporting"]

  NVD["NVD API"]
  KEV["CISA KEV"]
  RSS["RSS feeds"]
  OLL["Local LLM (Ollama)"]
  ELK["Elastic SIEM"]

  OUT["results/\nJSON · NDJSON · MD"]

  %% ===== Control flow =====
  MAIN --> CVE
  MAIN --> ART
  MAIN --> PDF
  MAIN --> GEO
  MAIN --> REP

  %% ===== Shared config =====
  MAIN --> CONFIG
  CVE --> CONFIG
  ART --> CONFIG
  PDF --> CONFIG
  GEO --> CONFIG
  REP --> CONFIG

  CVE --> PROG
  ART --> PROG
  PDF --> PROG
  GEO --> PROG
  REP --> PROG

  %% ===== External inputs =====
  CVE --> NVD
  CVE --> KEV
  ART --> RSS
  GEO --> RSS
  PDF -.-> OLL
  CVE -.-> OLL
  ART -.-> OLL
  REP -.-> OLL

  %% ===== Outputs =====
  CVE --> OUT
  ART --> OUT
  PDF --> OUT
  GEO --> OUT
  REP --> OUT

  %% ===== Delivery =====
  PDF --> ELK

  %% ===== Styling =====
  %% Control flow (blue)
  linkStyle 0,1,2,3,4 stroke:#1f77b4,stroke-width:2px

  %% Config / shared (purple)
  linkStyle 5,6,7,8,9,10,11,12,13,14 stroke:#9467bd,stroke-width:2px

  %% External data (orange)
  linkStyle 15,16,17,18 stroke:#ff7f0e,stroke-width:2px

  %% Optional LLM paths (gray)
  linkStyle 19,20,21,22 stroke:#999999,stroke-width:2px,stroke-dasharray:5 5

  %% Outputs (green)
  linkStyle 23,24,25,26,27 stroke:#2ca02c,stroke-width:2px

  %% Delivery (red)
  linkStyle 28 stroke:#d62728,stroke-width:2px