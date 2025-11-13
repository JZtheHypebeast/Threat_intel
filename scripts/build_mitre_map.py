import requests 
import json 
import re 
import os 
import logging 

MITRE_URL ="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT =os .path .join (os .path .dirname (os .path .dirname (__file__ )),"data","mitre_mapping.json")

# =============================================================================
#                    SCRIPTS - BUILD_MITRE_MAP
# =============================================================================
# Build script to fetch the MITRE ATT&CK bundle and produce a normalized
# mapping file (data/mitre_mapping.json).
# =============================================================================

def normalize (s ):
    s =s or ""
    s =s .lower ()
    s =re .sub (r"[^\w\s]"," ",s )
    s =re .sub (r"\s+"," ",s ).strip ()
    return s 

def main ():
    # BUILD SCRIPT #
    logging .basicConfig (level =logging .INFO )
    logger =logging .getLogger (__name__ )
    logger .info ("Fetching MITRE ATT&CK bundle...")
    r =requests .get (MITRE_URL ,timeout =30 )
    r .raise_for_status ()
    bundle =r .json ()
    mapping ={}

    for obj in bundle .get ("objects",[]):
        if obj .get ("type")!="attack-pattern":
            continue 
        name =obj .get ("name")
        tid =None 
        for ext in obj .get ("external_references",[])or []:
            if ext .get ("source_name")=="mitre-attack"and ext .get ("external_id","").startswith ("T"):
                tid =ext .get ("external_id")
                break 
        if not tid :
            continue 
        aliases =obj .get ("x_mitre_aliases")or []
        keys =[name ]+aliases 
        for k in keys :
            key =normalize (k )
            if not key :
                continue 
            mapping .setdefault (key ,[]).append ({
            "id":tid ,
            "name":name ,
            "url":f"https://attack.mitre.org/techniques/{tid}/"
            })

    os .makedirs (os .path .dirname (OUT ),exist_ok =True )
    with open (OUT ,"w",encoding ="utf-8")as f :
        json .dump (mapping ,f ,indent =2 ,ensure_ascii =False )

    logger .info (f"Wrote {len(mapping)} mapping keys -> {OUT}")


if __name__ =="__main__":
    main ()
