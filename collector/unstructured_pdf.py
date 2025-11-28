from __future__ import annotations

import os
import json
from datetime import datetime ,timezone

from pypdf import PdfReader

from .config import CONFIG ,logger ,write_jsonl ,mute_console ,safe_get
from .progress import progress_bar ,animate_progress
from .import delivery
from .unstructured_core import (
extract_threat_indicators ,
extract_iocs ,
compute_relevance_score ,
generate_actionable_items ,
generate_unstructured_markdown ,
_dehyphenate_text ,
save_full_text ,
_make_id ,
extract_top_findings ,
detect_provenance ,
normalize_and_merge_iocs ,
strip_provenance ,
extract_text_pdftotext ,
)
from .unstructured_core import (
summarize_unstructured_description ,
score_actionability ,
dedupe_records_by_title ,
infer_missing_vendor_and_actor ,
)

def extract_text_from_file (path ):
    texts =[]
    if os .path .isdir (path ):
        for root ,_ ,filenames in os .walk (path ):
            for fname in filenames :
                if not fname .lower ().endswith (".pdf"):
                    continue
                fp =os .path .join (root ,fname )
                try :
                    text =extract_text_pdftotext (fp )or None
                    meta ={}
                    if not text :
                        reader =PdfReader (fp )
                        text =" ".join ([p .extract_text ()or ""for p in reader .pages ])
                        try :
                            md =reader .metadata
                            if md :
                                if hasattr (md ,"items"):
                                    meta ={
                                    k .replace ("/",""):v for k ,v in md .items ()
                                    }
                                else :
                                    try :
                                        meta =dict (md )
                                    except Exception :
                                        meta ={}
                        except Exception :
                            meta ={}
                    texts .append ((os .path .basename (fp ),text or "",fp ,meta ))
                except Exception as e :
                    logger .warning (f"Failed to extract PDF {fp}: {e}")
    else :
        if str (path ).lower ().endswith (".pdf"):
            try :
                text =extract_text_pdftotext (path )or None
                meta ={}
                if not text :
                    reader =PdfReader (path )
                    text =" ".join ([p .extract_text ()or ""for p in reader .pages ])
                    try :
                        md =reader .metadata
                        if md :
                            if hasattr (md ,"items"):
                                meta ={k .replace ("/",""):v for k ,v in md .items ()}
                            else :
                                try :
                                    meta =dict (md )
                                except Exception :
                                    meta ={}
                    except Exception :
                        meta ={}
                texts .append ((os .path .basename (path ),text or "",path ,meta ))
            except Exception as e :
                logger .warning (f"Failed to extract PDF {path}: {e}")
    return texts

def run_unstructured_pdf_analysis (path =None ,hours =24 ):
    mute_console ()

    path =os .path .join (os .getcwd (),"data","PDF")
    files =extract_text_from_file (path )
    total =len (files )
    results =[]
    max_workers =CONFIG .get ("MAX_WORKERS",4 )
    if total :
        completed =0

        def _process_pdf (item ):
            meta ={}
            try :
                name ,text ,fp ,meta =item
            except Exception :
                try :
                    name ,text ,fp =item
                except Exception :
                    return None
            animate_progress (f"Analyzing {name}",20 )
            try :
                text =_dehyphenate_text (text )
            except Exception :
                pass

            try :
                full_text_path =save_full_text (text ,name )
            except Exception :
                full_text_path =None

            try :
                mtime =os .path .getmtime (fp )if fp else None
            except Exception :
                mtime =None
            try :
                text_id =_make_id (fp or name ,mtime )
            except Exception :
                text_id =None

            intel =extract_threat_indicators (text ,source =fp or name ,title =name )
            try :
                intel ["iocs"]=normalize_and_merge_iocs (text ,source =fp or name )
            except Exception :
                try :
                    intel ["iocs"]=extract_iocs (text ,source =fp or name ,title =name )
                except Exception :
                    intel ["iocs"]=[]
            if CONFIG .get ("ENABLE_SUMMARIZATION"):
                try :
                    intel ["summary_text"]=summarize_unstructured_description (
                    text ,max_sentences =2
                    )
                except Exception :
                    pass
            if CONFIG .get ("ENABLE_SCORING"):
                intel =compute_relevance_score (intel )
            try :
                actions =generate_actionable_items (intel )
                if isinstance (actions ,dict ):
                    intel .update (actions )
            except Exception :
                pass
            try :
                mtime =os .path .getmtime (fp )
                intel ["@timestamp"]=datetime .fromtimestamp (
                mtime ,timezone .utc
                ).isoformat ()
            except Exception :
                intel ["@timestamp"]=datetime .now (timezone .utc ).isoformat ()
            intel ["source"]=fp
            intel ["full_text_path"]=full_text_path
            intel ["text_id"]=text_id
            try :
                intel ["top_findings"]=extract_top_findings (text ,k =5 )
            except Exception :
                intel ["top_findings"]=[]

            try :
                prov =detect_provenance (text )or []
            except Exception :
                prov =[]

            try :
                if meta :
                    t =meta .get ("Title")or meta .get ("title")
                    if t :
                        prov .append (
                        {
                        "source_name":t ,
                        "source_url":None ,
                        "confidence":0.7 ,
                        "excerpt":"PDF metadata: Title",
                        "pos":0 ,
                        }
                        )
                    a =meta .get ("Author")or meta .get ("author")
                    if a :
                        prov .append (
                        {
                        "source_name":a ,
                        "source_url":None ,
                        "confidence":0.6 ,
                        "excerpt":"PDF metadata: Author",
                        "pos":0 ,
                        }
                        )
            except Exception :
                pass

            try :
                intel ["provenance"]=prov
            except Exception :
                intel ["provenance"]=[]
            return intel

        completed =0
        for f in files :
            completed +=1
            progress_bar (completed ,total ,prefix ="PDF analyzed")
            try :
                res =_process_pdf (f )
            except Exception as e :
                fp =None
                try :
                    fp =f [2 ]
                except Exception :
                    fp =None
                logger .warning (f"Error processing PDF {fp or '<unknown>'}: {e}")
                res =None
            if res :
                results .append (res )
                try :
                    print (f"DEBUG: appended result source={res.get('source')}")
                except Exception :
                    pass

    date_stamp =datetime .now ().strftime ("%Y%m%d")
    ndjson_path =os .path .join (
    CONFIG ["OUTPUT_DIR"],f"UnstructuredPDFIntel_{date_stamp}.ndjson"
    )
    try :

        try :
            inferred =infer_missing_vendor_and_actor (results )
            if isinstance (inferred ,list )and inferred :
                results =inferred
        except Exception :
            pass

        for r in results :
            try :
                if CONFIG .get ("ENABLE_SUMMARIZATION"):
                    r ["summary_text"]=summarize_unstructured_description (
                    r .get ("full_text_path")and ""or r .get ("text",""),
                    max_sentences =2 ,
                    )
            except Exception :
                pass
            try :
                act =score_actionability (
                r .get ("title"),
                r .get ("summary_text")or " ".join (r .get ("top_findings")or []),
                )
                if act :
                    r .setdefault ("threat",{})
                    r ["threat"]["actionability"]=act
            except Exception :
                pass

        try :
            results =dedupe_records_by_title (results ,fuzzy_threshold =0.95 )
        except Exception :
            pass

        sanitized =[strip_provenance (r )for r in results ]
    except Exception :
        sanitized =results

    write_jsonl (ndjson_path ,sanitized )
    try :
        if CONFIG .get ("EXPORT_NAVIGATOR"):
            from collections import Counter

            counts =Counter ()
            for r in results :
                for m in safe_get (r ,"threat.technique.mitre",[])or []:
                    tid =m .get ("id")
                    if tid :
                        counts [tid ]+=1
            if counts :
                top =max (counts .values ())
                layer ={
                "name":"Observed Techniques",
                "description":"Auto-generated layer",
                "techniques":[],
                }
                for tid ,c in counts .items ():
                    score =int ((c /top )*100 )if top else 0
                    layer ["techniques"].append (
                    {
                    "techniqueID":tid ,
                    "score":score ,
                    "comment":f"{c} occurrences",
                    }
                    )
                nav_path =os .path .join (
                CONFIG ["OUTPUT_DIR"],f"navigator_layer_{date_stamp}.json"
                )
                with open (nav_path ,"w",encoding ="utf-8")as nf :
                    json .dump (layer ,nf ,indent =2 )
    except Exception :
        pass

    generate_unstructured_markdown (
    sanitized ,
    "Unstructured PDF Intelligence Report",
    f"UnstructuredPDFReport_{date_stamp}.md",
    )
    try :
        if CONFIG .get ("SIEM_ENABLED")and CONFIG .get ("SIEM_TYPE")=="elastic":
            delivery .send_batch_to_elastic (sanitized )
    except Exception as e :
        logger .warning (f"SIEM delivery failed: {e}")

    return {"records":len (results ),"ndjson":ndjson_path }
