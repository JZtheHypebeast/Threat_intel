
"""Diagnostic harness to inspect pattern/phrase/MITRE matching for unstructured items.
Usage:
  python3 scripts/debug_mitre_mapping.py --input collector/results/20251128/UnstructuredRSSIntel_20251128.ndjson --limit 20
"""
import argparse
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional

from collector import unstructured_core as uc

def inspect_file (path :Path ,limit :int =20 ,out_path :Optional [Path ]=None ):
    compiled =uc .load_compiled_patterns ()or {}
    pm =uc .load_mitre_phrase_map ()or {}
    mit_map =uc .load_mitre_map ()or {}

    results =[]
    with path .open (encoding ="utf-8")as f :
        for i ,line in enumerate (f ):
            if limit and i >=limit :
                break
            line =line .strip ()
            if not line :
                continue
            try :
                rec =json .loads (line )
            except Exception :
                continue
            title =rec .get ("title")
            text ="\n".join (
            str (rec .get (k )or "")
            for k in (
            "title",
            "summary_text",
            "summary",
            "text",
            "full_text",
            "description",
            )
            if rec .get (k )
            )
            sample ={"index":i ,"title":title }

            try :
                label =uc .classify_threat (text )
            except Exception :
                label =None
            sample ["classification"]=label

            pat_matches =[]
            for key ,lst in compiled .items ():
                for it in lst :
                    rg =it .get ("regex")
                    if not rg :
                        continue
                    try :
                        if rg .search (text ):
                            pat_matches .append ({"key":key ,"pattern":it .get ("pattern")or it .get ("regex_repr")})
                            break
                    except re .error :
                        continue
            sample ["pattern_matches"]=pat_matches

            phrase_matches =[]
            for phrase in list (pm .keys ()):
                try :
                    if re .search (r"(?i)\\b"+re .escape (phrase )+r"\\b",text ):
                        phrase_matches .append (phrase )
                except re .error :
                    continue
            sample ["phrase_map_matches"]=phrase_matches

            extracted =uc .extract_threat_indicators ({"title":title ,"text":text })
            sample ["extracted_technique"]=extracted .get ("threat",{}).get ("technique")
            sample ["mitre_details"]=extracted .get ("threat",{}).get ("mitre_details")

            sample ["excerpt"]=(text or "")[:400 ].replace ("\n"," ")

            results .append (sample )

    if out_path :
        out_path .parent .mkdir (parents =True ,exist_ok =True )
        with out_path .open ("w",encoding ="utf-8")as outf :
            for r in results :
                outf .write (json .dumps (r ,ensure_ascii =False )+"\n")
        print (f"Wrote diagnostics to {out_path}")

    for r in results :
        print ("---\n#%d: %s"%(r ["index"],r .get ("title")or "(no title)"))
        print ("Classification:",r .get ("classification"))
        print ("Pattern matches:",[p ["key"]for p in r .get ("pattern_matches",[])])
        print ("Phrase map matches:",r .get ("phrase_map_matches"))
        print ("Extracted technique:",r .get ("extracted_technique"))
        print ("MITRE details:",r .get ("mitre_details"))
        print ("Excerpt:",r .get ("excerpt"))

    return results

if __name__ =="__main__":
    ap =argparse .ArgumentParser ()
    ap .add_argument ("--input",required =True ,help ="NDJSON file to inspect")
    ap .add_argument ("--limit",type =int ,default =20 ,help ="Number of records to inspect")
    ap .add_argument ("--out",help ="Optional output JSONL path for diagnostics")
    args =ap .parse_args ()

    in_path =Path (args .input )
    if not in_path .exists ():
        print ("Input file not found:",in_path )
        raise SystemExit (1 )
    out_path =Path (args .out )if args .out else Path ("collector/logs/mitre_debug_%s.ndjson"%datetime .now ().strftime ("%Y%m%d_%H%M%S"))
    inspect_file (in_path ,args .limit ,out_path )
