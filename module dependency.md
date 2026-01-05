flowchart LR
  MAIN["main.py"]
  CONFIG["config.py"]
  PROG["progress.py"]

  CVE["CVE.py"]
  ART["articles.py"]
  PDF["pdf.py"]
  GEO["geofeed.py"]
  REP["reporting.py"]
  DELIV["delivery.py"]

  MAIN --> CONFIG
  MAIN --> CVE
  MAIN --> ART
  MAIN --> PDF
  MAIN --> GEO
  MAIN --> REP

  CVE --> CONFIG
  CVE --> PROG
  CVE --> ART

  ART --> CONFIG
  ART --> PROG

  PDF --> CONFIG
  PDF --> PROG
  PDF --> ART
  PDF --> DELIV

  DELIV --> CONFIG

  GEO --> CONFIG
  GEO --> PROG
  GEO --> REP

  REP --> CONFIG
  REP --> PROG

  %% Styling
  %% Entry point
  linkStyle 0,1,2,3,4,5 stroke:#1f77b4,stroke-width:2px

  %% Core dependencies
  linkStyle 6,7,8,9,10,11,12,13 stroke:#9467bd,stroke-width:2px

  %% Cross-module coupling
  linkStyle 14,15,16 stroke:#ff7f0e,stroke-width:2px
