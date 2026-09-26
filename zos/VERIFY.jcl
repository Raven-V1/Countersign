//* VERIFY.jcl -- Verify a Countersign record on USS.
//* Record name placeholder replaced by countersign.py at submit time.
//* Never submit this template directly.
//VERIFY   JOB CLASS=A,MSGCLASS=H,MSGLEVEL=(1,1),NOTIFY=&SYSUID
//STEP1    EXEC PGM=BPXBATCH
//STDPARM  DD *
SH PY=/usr/lpp/IBM/cyp/v3r9/pyz/bin/python3;
chtag -tc ISO8859-1 $HOME/countersign/verify_record.py;
VREC=$HOME/countersign/verify_record.py;
REC=$HOME/countersign/%%RECORD_NAME%%;
HASH=%%EXPECTED_HASH%%;
$PY $VREC $REC $HASH
/*
//STDOUT   DD SYSOUT=*
//STDERR   DD SYSOUT=*
