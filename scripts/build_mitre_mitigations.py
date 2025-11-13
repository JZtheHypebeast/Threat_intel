import requests 
import json 
import os 
from collections import defaultdict 

MITRE_URL ="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT =os .path .join (os .path .dirname (os .path .dirname (__file__ )),"data","mitre_mitigations.json")

# =============================================================================
#              SCRIPTS - BUILD_MITRE_MITIGATIONS
# =============================================================================
# Build script that extracts course-of-action (mitigation) mappings from the
# MITRE ATT&CK bundle and writes data/mitre_mitigations.json.
# =============================================================================

def main ():
    # BUILD SCRIPT #
    print ("Fetching MITRE ATT&CK bundle...")
    r =requests .get (MITRE_URL ,timeout =30 )
    r .raise_for_status ()
    bundle =r .json ()

    objs ={o .get ('id'):o for o in bundle .get ('objects',[])}

    coa_objs ={o ['id']:o for o in objs .values ()if o .get ('type')=='course-of-action'}

    mitig_map =defaultdict (lambda :{"title":"","recommendations":[],"snippets":{}})

    for o in bundle .get ('objects',[]):
        if o .get ('type')!='relationship':
            continue 
        if o .get ('relationship_type')!='mitigates':
            continue 
        src =o .get ('source_ref')
        tgt =o .get ('target_ref')

        if src in coa_objs and tgt and objs .get (tgt )and objs [tgt ].get ('type')=='attack-pattern':
            coa =coa_objs [src ]
            ap =objs [tgt ]
        elif tgt in coa_objs and src and objs .get (src )and objs [src ].get ('type')=='attack-pattern':
            coa =coa_objs [tgt ]
            ap =objs [src ]
        else :
            continue 


        tid =None 
        for ext in ap .get ('external_references',[])or []:
            if ext .get ('source_name')=='mitre-attack'and ext .get ('external_id','').startswith ('T'):
                tid =ext .get ('external_id')
                break 
        if not tid :
            continue 

        title =coa .get ('name')or ''
        descr =coa .get ('description')or ''

        entry =mitig_map [tid ]
        if not entry ['title']:
            entry ['title']=ap .get ('name')or ''

        if title and title not in entry ['recommendations']:
            entry ['recommendations'].append (title )
        if descr and descr not in entry ['recommendations']:
            entry ['recommendations'].append (descr )
        for line in (descr or '').splitlines ():
            s =line .strip ()
            if not s :
                continue 

            if len (s )<200 :
                entry ['snippets'].setdefault ('action',[]).append (s )


    out ={}
    for k ,v in mitig_map .items ():

        recs =[]
        seen =set ()
        for r in v ['recommendations']:
            if r and r not in seen :
                recs .append (r )
                seen .add (r )
        snippets ={}
        for stype ,sarr in v ['snippets'].items ():

            out_arr =[]
            sseen =set ()
            for s in sarr :
                if s not in sseen :
                    out_arr .append (s )
                    sseen .add (s )
            snippets [stype ]=out_arr 
        out [k ]={"title":v ['title'],"recommendations":recs ,"snippets":snippets }

    os .makedirs (os .path .dirname (OUT ),exist_ok =True )
    with open (OUT ,'w',encoding ='utf-8')as f :
        json .dump (out ,f ,indent =2 ,ensure_ascii =False )

    print (f"Wrote mitigations for {len(out)} techniques -> {OUT}")

if __name__ =='__main__':
    main ()
