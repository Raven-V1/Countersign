//* PROBE.jcl -- Discover USS Python 3 path on Z Xplore.
//* Submit with:
//*   zowe zos-jobs submit local-file zos/PROBE.jcl
//*     --wait-for-output --view-all-spool-content
//* Paste SYSOUT into countersign-plan.md section 5.0.
//PROBE    JOB CLASS=A,MSGCLASS=H,MSGLEVEL=(1,1),NOTIFY=&SYSUID
//STEP1    EXEC PGM=BPXBATCH
//STDPARM  DD *
SH id; uname -a; echo $PATH; command -v python3;
python3 --version; ls -d /usr/lpp/IBM/cyp/*/pyz/bin 2>/dev/null
/*
//STDOUT   DD SYSOUT=*
//STDERR   DD SYSOUT=*
