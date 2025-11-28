import os
import re
import tempfile

from collector .unstructured_core import (
_dehyphenate_text ,
detect_provenance ,
extract_top_findings ,
normalize_and_merge_iocs ,
save_full_text ,
)

def test_dehyphenate ():
    s ="This is a hyphen-\nated word and a new\nline. Another line."
    out =_dehyphenate_text (s )
    assert "hyphenated"in out
    assert "\n"not in out

def test_normalize_merge_iocs_basic ():
    text ="Contact us at badguy@example.com and visit http://mal.example.com/path. Hash: abcdef1234567890"
    res =normalize_and_merge_iocs (text ,source ="test")

    types ={r ["type"]for r in res }
    assert "email"in types or "url"in types or "hash"in types

def test_extract_top_findings_simple ():
    text =(
    "This document describes a ransomware attack. The attackers used a new exploit. "
    "There was data exfiltration of 2TB. Another unrelated short line."
    )
    tf =extract_top_findings (text ,k =3 )
    assert isinstance (tf ,list )
    assert any ("ransomware"in s .lower ()for s in tf )

def test_detect_provenance ():
    text =(
    "Source: ACME Threat Research\nSome other text mentioning Microsoft and ACME."
    )

    prov =detect_provenance (text )
    assert isinstance (prov ,list )
    assert any ("acme"in p .get ("source_name","").lower ()for p in prov )

def test_save_full_text_writes_file (tmp_path ):
    text ="sample text for file"
    filename ="testfile.pdf"

    from collector .config import CONFIG as _C

    old =_C .get ("OUTPUT_DIR")
    _C ["OUTPUT_DIR"]=str (tmp_path )
    try :
        p =save_full_text (text ,filename )
        assert os .path .exists (p )
        with open (p ,"r",encoding ="utf-8")as fh :
            got =fh .read ()
        assert "sample text"in got
    finally :
        if old is None :
            _C .pop ("OUTPUT_DIR",None )
        else :
            _C ["OUTPUT_DIR"]=old
