$ ! VMS$AUDIT.COM --                                               'F$VERIFY(0)'
$ !
$ ! Copyright � 2014 by Lorin Ricker.  All rights reserved, with acceptance,
$ ! use, modification and/or distribution permissions as granted and controlled
$ ! by and under the GPL described herein.
$ !
$ ! This program (software) is Free Software, licensed under the terms and
$ ! conditions of the GNU General Public License Version 3 as published by
$ ! the Free Software Foundation: http://www.gnu.org/copyleft/gpl.txt,
$ ! which is hereby incorporated into this software and is a non-severable
$ ! part thereof.  You have specific rights and obligations under this GPL
$ ! which are binding if and when you accept, use, modify and/or distribute
$ ! this software program (source code file) and/or derivatives thereof.
$ !
$ !   Performs a comprehensive audit of a VMS (OpenVMS) System using
$ !   administrative (system management) level commands and utilties.
$ !   Outputs report to a file (for review, analysis and archival) or
$ !   directly to screen (for development checkout).
$ !
$ ! usage:  @VMS$AUDIT [ AUDIT (D) | GENERATE (D) | CLEANUP
$ !                      | REVIEW | TYPE | EDIT | HELP ]
$ !
$ ! ========================
$ ! Release History:
$ !  12-DEC-2014 : Official re-release, version# updated.
$ !  12-NOV-2014 : Reorganized steps to promote selected summaries to
$ !                the top/front of the report.
$ !  02-SEP-2014 : Added UAF$QUICK_ANALYSIS.COM to report total users,
$ !                total priv'd users, disuser'd users and disuser'd
$ !                priv'd users.
$ !  17-Jul-2014 : Added displays for system's STARTUP command files.
$ !                Improved display of SYSGEN parameters.
$ !                Added dir-listing of LMF$*.LDB files.
$ !  16-Jul-2014 : Correct syntax for NCL's version of "SHOW KNOWN
$ !                NODES" --> "SHOW NODE 0 ROUTING CIRCUIT CSMA-CD
$ !                ADJACENCY * ALL STATUS" (whew!).  Also reordered
$ !                the NCP and NCL commands for DECnet IV and V.
$ !  24-Jun-2014 : Add AuditStep "TYPE SYS$UPDATE:VMSINSTAL.HISTORY".
$ !                Some file-purge cleanup for BACKUP and ZIP.
$ !  23-Jun-2014 : Add AuditStep "SHOW ERRORS" (lost-in-shuffle!).
$ !                Improve rename-filespec for each SYSUAF.LIS
$ !                to include nodename.
$ !  19-Jun-2014 : Refinements to reporting the SYSUAF, in
$ !                particular, write LIST /FULL and /BRIEF
$ !                reports out to separate .LIS files rather
$ !                than into the main .REPORT; easier to
$ !                search/count/process that way.
$ !  18-Jun-2014 : Add a SHOW QUEUE /FULL step just before
$ !                the QUE$STALLED.COM check; re-ordered the
$ !                VI.a. & g. steps for clarity in review;
$ !                removed ":SS" from VA$TimeStamp (too fussy);
$ !                added BACKUP and RESTORE functions (similar
$ !                to ZIP and UNZIP)
$ !  17-Jun-2014 : Autodetect installed network products,
$ !                don't prompt for them; add Multinet stub;
$ !                cannot auto-drive BOOT_OPTIONS.COM for
$ !                VMS versions < v8.4 (!)
$ !  16-Jun-2014 : Bug fixes; improved ON SEVERE_ERROR handling
$ !                for the Target Command; handle zip/unzip better;
$ !                created/added QUE$STALLED.COM to detect Queues
$ !                with excessive jobs (usually stalled)
$ !  29-May-2014 : Baseline functionality in place
$ !  28-May-2014 : Proof-of-concept; core functions working
$ ! ========================
$ !
$TimeStamp:  SUBROUTINE
$ ! P1 : timestamp to format (empty "" means "NOW")
$ !
$ ON CONTROL_Y THEN GOSUB TSCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ VA$TimeStamp == "at "  + F$CVTIME(P1,"ABSOLUTE","HOUR")    -
                + ":"    + F$CVTIME(P1,"ABSOLUTE","MINUTE")  -
                + " on " + F$CVTIME(P1,"ABSOLUTE","WEEKDAY") -
                + ", "   + F$CVTIME(P1,"ABSOLUTE","DATE")
$ EXIT 1
$TSCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! TimeStamp
$ !
$NetInstalled:  SUBROUTINE
$ ! P1 : network to detect
$ Sym = P1 - "/"  ! cleanout any punctuation, e.g., "TCP/IP" -> "TCPIP"
$ !
$ PIPE SHOW NET | SEARCH SYS$INPUT "''P1'" /NOOUTPUT /NOWARNINGS ; netstatus = ( $STATUS .EQS. "%X10000001" )
$ VA$'Sym'Inst == netstatus
$ !! show symbol VA$'Sym'Inst
$ EXIT 1
$ !
$ ENDSUBROUTINE  ! NetInstalled
$ !
$CenterLine:  SUBROUTINE
$ ! P1 : text to center
$ !
$ ON CONTROL_Y THEN GOSUB CLCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ P1L = F$LENGTH(P1)
$ Indent = ( VA$PgWi - P1L ) / 2
$ wso F$FAO( "!#* !AS", Indent, P1 )
$ EXIT 1
$CLCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! CenterLine
$ !
$ReportHeader:  SUBROUTINE
$ ! P1 : Facility name
$ ! P2 : Procedure filespec
$ ! P3 : Procedure version
$ ! P4 : Nodename
$ ! P5 : Report date (started)
$ ! P6 : Username (report generator)
$ !
$ ON CONTROL_Y THEN GOSUB RHCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ wso F$FAO( "!#*=", VA$PgWi )
$ wso ""
$ msg = F$FAO( "!AS -- VMS/OpenVMS Audit Report -- The PARSEC Group", P1 )
$ CALL CenterLine "''msg'"
$ msg = F$FAO( "!AS", P2 )
$ CALL CenterLine "''msg'"
$ msg = F$FAO( "!AS", P3 )
$ CALL CenterLine "''msg'"
$ msg = F$FAO( "Report run on system/node !AS", P4 )
$ CALL CenterLine "''msg'"
$ msg = F$FAO( "!AS", P5 )
$ CALL CenterLine "''msg'"
$ msg = F$FAO( "by !AS (login: !AS)", P6, F$EDIT(F$GETJPI("","USERNAME"),"TRIM") )
$ CALL CenterLine "''msg'"
$ msg = "Copyright � 2014 by The PARSEC Group.  All rights reserved."
$ CALL CenterLine "''msg'"
$ wso ""
$ wso F$FAO( "!#*=", VA$PgWi )
$ wso ""
$ wso ""
$ EXIT 1
$RHCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! ReportHeader
$ !
$ReportFooter:  SUBROUTINE
$ ! P1 : Facility name
$ ! P2 : Nodename
$ ! P3 : Report date (ended)
$ !
$ ON CONTROL_Y THEN GOSUB RFCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ wso ""
$ wso VA$DblDashes
$ wso ""
$ msg = F$FAO( "!AS -- End of VMS/OpenVMS Audit Report -- The PARSEC Group", P1 )
$ CALL CenterLine "''msg'"
$ msg = F$FAO( "for system/node !AS", P2 )
$ CALL CenterLine "''msg'"
$ msg = F$FAO( "!AS", P3 )
$ CALL CenterLine "''msg'"
$ wso ""
$ wso VA$DblDashes
$ EXIT 1
$RFCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! ReportFooter
$ !
$ !
$Paginate:  SUBROUTINE
$ ! P1 : "NOPAGE" to suppress pagination <FF>
$ !
$ ON CONTROL_Y THEN GOSUB PgCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ IF OutToFile
$ THEN IF ( F$EDIT(F$EXTRACT(0,3,P1),"UPCASE") .EQS. "NOP" )
$      THEN wso ""
$           VA$PgStr == ""
$      ELSE wso ""     ! form-feed, eject page, format and count it
$           VA$PgStr == F$FAO( "page !SL", VA$PgNo )
$           VA$PgNo  == VA$PgNo + 1
$      ENDIF
$ ELSE wso ""
$      VA$PgStr == ""
$ ENDIF
$ EXIT 1
$PgCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! Paginate
$ !
$Header:  SUBROUTINE
$ ! P1: Command text to display in header box
$ ! P2: "NOPAGE" to suppress pagination <FF>
$ !
$ ON CONTROL_Y THEN GOSUB HdrCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ P1L = F$LENGTH(P1)
$ LPadP1 = ( VA$PgWi - P1L ) / 2
$ CALL TimeStamp ""   ! global VA$TimeStamp
$ TSL = F$LENGTH(VA$TimeStamp)
$ LPadNow = ( VA$PgWi - TSL ) / 2
$ RPadNow = LPadNow
$ IF ( (LPadNow * 2) .LT. (VA$PgWi - TSL) ) THEN RPadNow = RPadNow + 1
$ CALL Paginate "''P2'"
$ wso VA$Dashes
$ wso ""
$ IF OutToFile
$ THEN wso F$FAO( "!#* !AS", LPadP1, P1 )
$ ELSE wso F$FAO( "!#* [4m!AS[0m", LPadP1, P1 )
$ ENDIF
$ wso ""
$ wso F$FAO( "!#* !AS", LPadNow, VA$TimeStamp )
$ IF ( VA$PgStr .NES. "" )
$ THEN wso F$FAO( "!#* !AS", VA$PgWi - F$LENGTH(VA$PgStr) - 1, VA$PgStr )
$ ELSE wso ""
$ ENDIF
$ wso VA$Dashes
$ wso ""
$ wso ""
$ EXIT 1
$HdrCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! Header
$ !
$Footer:  SUBROUTINE
$ ! (no parameters)
$ ON CONTROL_Y THEN GOSUB FtrCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ wso ""
$ wso VA$DblDashes
$ wso ""
$ wso ""
$ EXIT 1
$FtrCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! Footer
$ !
$UAFsetup:  SUBROUTINE
$ ! P1 : Command
$ IF ( F$TRNLNM("SYSUAF","LNM$SYSTEM") .EQS. "" )
$ THEN DEFINE /PROCESS /NOLOG sysuaf SYS$SYSTEM:SYSUAF.DAT
$      DEFINE /PROCESS /NOLOG rightslist SYS$SYSTEM:RIGHTSLIST.DAT
$ ENDIF
$ EXIT 1
$ ENDSUBROUTINE  ! UAFsetup
$ !
$UAFteardown:  SUBROUTINE
$ ! P1 : Command
$ IF ( F$TRNLNM("SYSUAF","LNM$PROCESS") .NES. "" )
$ THEN DEASSIGN /NOLOG /PROCESS sysuaf
$      DEASSIGN /NOLOG /PROCESS rightslist
$ ENDIF
$ IF ( F$SEARCH("[]SYSUAF.LIS") .NES. "" )
$ THEN ! AUTHORIZE is simplistic about naming LIST files, so fix:
$      IF ( F$LOCATE("/FULL",P1) .LT. F$LENGTH(P1) )
$      THEN RENAME /NOLOG []SYSUAF.LIS []'Fac'_'Node'_SYSUAF_FULL.LIS
$      ELSE RENAME /NOLOG []SYSUAF.LIS []'Fac'_'Node'_SYSUAF_BRIEF.LIS
$           ! Not very modular, but let's do some account analysis here, too:
$           @'DD'UAF$QUICK_ANALYSIS "[]''Fac'_''Node'_SYSUAF_BRIEF.LIS"
$      ENDIF
$ ENDIF
$ EXIT 1
$ ENDSUBROUTINE  ! UAFteardown
$ !
$AuditStep:  SUBROUTINE
$ ! P1: Command to execute (and put in Header)
$ ! P2: "NOPAGE" to suppress pagination <FF>
$ ! P3: Alternate text for Header (defaults to P1)
$ !
$ ON CONTROL_Y THEN GOSUB ASCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ UAFlag = F$EXTRACT(0,6,P1) .EQS. "V$AUTH"
$ IF ( P3 .EQS. "" ) THEN P3 = P1
$ CALL Header "''P3'" "''P2'"
$ IF Debugging THEN wserr "%''Fac'-I-PROGRESS, ''P3'..."
$ IF OutToFile
$ THEN wso "$ ''P3'"
$ ELSE wso "$ [1m''P3'[0m"
$ ENDIF
$ ON SEVERE_ERROR THEN CONTINUE  ! never say die!
$ IF UAFlag THEN CALL UAFsetup "''P1'"
$ ! ---------
$ 'P1'
$ ! ---------
$ IF UAFlag THEN CALL UAFteardown "''P1'"
$ ON ERROR THEN EXIT %X2C
$ CALL Footer
$ IF ( .NOT. OutToFile )  ! reporting to terminal, interactive...
$ THEN wso ""
$      READ sys$command junk /END_OF_FILE=ASDone -
         /PROMPT="[1m<Ctrl/Z> to quit, <Enter> to continue:[0m "
$ ENDIF
$ EXIT 1
$ASDone:
$ EXIT %X2C
$ASCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! AuditStep
$ !
$Cleaner:  SUBROUTINE
$ ! P1 : Filespec to clean
$ ! P2 : Plug-in name
$ ! P3 : Plug-in filespec
$ !
$ ON CONTROL_Y THEN GOSUB ClCtrl_Y
$ ON ERROR THEN EXIT %X2C
$ IF Debugging THEN wserr "%''Fac'-I-PROGRESS, cleaning ''P3' with ''P2'..."
$ ! Suppress TPU's naturally noisey output --
$ DEFINE /USER_MODE /NOLOG sys$error  nl:
$ DEFINE /USER_MODE /NOLOG sys$output nl:
$ !
$ EDIT /TPU /NODISPLAY /NOSECTION /NOJOURNAL -
    /COMMAND='P3' 'P1'
$ Stat = $STATUS
$ !
$ IF Stat .AND. ( .NOT. Debugging )
$ THEN vn  = F$PARSE(P1,,,"VERSION") - ";"
$      vno = F$INTEGER(vn) - 1
$      PURGE /SINCE=TODAY 'P1'
$      RENAME 'P1' *.*;'vno'
$ ENDIF
$ EXIT 1
$ !
$ClCtrl_Y:
$ RETURN %X2C
$ ENDSUBROUTINE  ! Cleaner
$ !
$ !
$ ! ========================
$MAIN:
$ SET CONTROL=(Y,T)
$ ON CONTROL THEN GOSUB Ctrl_Y
$ ON ERROR THEN GOTO Done
$ !
$ ProcVersion = "V1.2-01 (12-Dec-2014)"
$ !
$ Proc   = F$ENVIRONMENT("PROCEDURE")
$ Fac    = F$PARSE(Proc,,,"NAME","SYNTAX_ONLY")
$ Dir    = F$PARSE(Proc,,,"DIRECTORY","SYNTAX_ONLY")
$ Dev    = F$PARSE(Proc,,,"DEVICE","SYNTAX_ONLY")
$ DD     = Dev + Dir
$ Node   = F$GETSYI("NODENAME")
$ VMSver = F$GETSYI("VERSION")
$ !
$ Debugging = F$TRNLNM("TOOLS$DEBUG")
$ !
$ ! Define a global command symbol, just for convenience:
$ IF F$TYPE(vmsaudit) .EQS. "" THEN vmsau*dit == "@''DD'VMS$Audit.com"
$ !
$ V$AUTH     = "MCR AUTHORIZE"
$ V$LANCP    = "MCR LANCP"
$ V$SYSGEN   = "MCR SYSGEN"
$ V$SYSMAN   = "MCR SYSMAN"
$ V$IFCONFIG = "$SYS$SYSTEM:TCPIP$IFCONFIG"
$ V$NCP      = "MCR NCP"
$ V$NCL      = "MCR NCL"
$ V$DIR      = "DIRECTORY /SIZE /OWNER /DATE /PROTECTION /WIDTH=(FILENAME=20,SIZE=9,OWNER=16)"
$ V$Star     = "*"
$ V$BckSSN   = Fac
$ V$BckList  = "''Fac'.com;,''Fac'_*.tpu;,''Fac'_boot_options.answers;,que$stalled.com;,uaf$quick_analysis.com;,quick_audit.com;"
$ V$ZipArc   = "''Fac'.zip"
$ V$ZipList  = "''Fac'.com ''Fac'_*.tpu ''Fac'_boot_options.answers que$stalled.com uaf$quick_analysis.com quick_audit.com"
$ !
$ wso    = "WRITE sys$output"
$ wserr  = "WRITE sys$error"
$ !
$ OutToFile = "FALSE"
$ !
$ VA$PgNo      ==  1
$ VA$PgWi      == 78
$ VA$Dashes    == F$FAO( "!#*-", VA$PgWi )
$ VA$DblDashes == F$FAO( "!#*=", VA$PgWi )
$ !
$ CALL TimeStamp ""   ! global VA$TimeStamp
$ !
$ ! ========================
$ !
$ IF ( P1 .NES. "" )
$ THEN IF ( P1 .EQS. "?" ) THEN P1 = "HELP"
$      GOTO 'F$EXTRACT(0,3,P1)'$           ! No P1? (default) Generate the audit...
$ ENDIF
$ !
$GEN$:   ! Generate the Audit Report
$AUD$:
$ wserr F$FAO( "!/%!AS-I-START, [4mVMS Audit Report[0m !AS starting at [1m!AS[0m...!/", Fac, ProcVersion, VA$TimeStamp )
$ READ sys$command User /END_OF_FILE=Done /PROMPT="Enter your full name: "
$ User = F$EDIT(User,"TRIM,COMPRESS")
$ !
$ deffile = F$PARSE("''Fac'_''Node'","''Dev'''Dir'.REPORT",,,"SYNTAX_ONLY") - ";"
$ !
$ wso ""
$ wso "  Choices for output file --"
$ wso "    Terminal display: [1m''V$Star'[0m"
$ wso "    [4m''deffile'[0m: <Enter>"
$ wso "    Other file: filename"
$ wso ""
$ READ sys$command Answer /END_OF_FILE=Done /PROMPT="Report output file: "
$ Answer = F$PARSE(Answer,deffile,,"NAME","SYNTAX_ONLY")
$ IF Debugging THEN wserr "%''Fac'-I-OUTFILE, output file: ""''Answer'"""
$ IF ( Answer .NES. V$Star )
$ THEN Answer = F$PARSE(Answer,deffile,,,"SYNTAX_ONLY") - ";"
$      DEFINE /NOLOG /PROCESS sys$output 'Answer'
$      OutToFile = "TRUE"
$      VA$AuditReport == Answer    ! Save output filespec as a global symbol, don't delete it on exit...
$ ENDIF
$ !
$ NeedPrv = "SYSNAM,SYSPRV,SECURITY,CMKRNL,VOLPRO,BYPASS,OPER"
$ prv = F$SETPRV(NeedPrv)
$ IF .NOT. F$PRIVILEGE(NeedPrv)
$ THEN wso F$FAO( "%!AS-E-INSUFFPRV, need !AS", Fac, NeedPrv )
$      GOTO Done
$ ENDIF
$ !
$ !
$ ! ========================
$ !
$ CALL NetInstalled "DECnet"
$ CALL NetInstalled "TCP/IP"
$ CALL NetInstalled "Multinet"
$ !
$ CALL ReportHeader "''Fac'" "''Proc'" "''ProcVersion'" "''Node'" "''VA$TimeStamp'" "''User'"
$ !
$ ! ========================
$ ! I. System Summaries:
$ CALL AuditStep "SHOW SYSTEM /HEADER /NOPROCESS /GRAND_TOTAL"
$ CALL AuditStep "SHOW NETWORK" "NOPAGE"
$ CALL AuditStep "SHOW CLUSTER" "NOPAGE"
$ CALL AuditStep "SHOW ERROR"   "NOPAGE"
$ !
$ CALL AuditStep "SHOW MEMORY /FILES"
$ CALL AuditStep "V$DIR SYS$SYSTEM:*FILE.SYS;*,*DUMP*.DMP;*" "NOPAGE" "DIRECTORY SYS$SYSTEM:*FILE.SYS,*DUMP*.DMP"
$ !
$ IF ( F$TRNLNM("SYSUAF","LNM$SYSTEM_DIRECTORY") .NES. "" )
$ THEN CALL AuditStep "SHOW LOGICAL /FULL SYSUAF"          ""
$      CALL AuditStep "SHOW LOGICAL /FULL RIGHTSLIST"      "NOPAGE"
$      CALL AuditStep "SHOW LOGICAL /FULL NETPROXY"        "NOPAGE"
$      CALL AuditStep "SHOW LOGICAL /FULL NET$PROXY"       "NOPAGE"
$      CALL AuditStep "SHOW LOGICAL /FULL VMSMAIL_PROFILE" "NOPAGE"
$      CALL AuditStep "V$DIR SYSUAF,RIGHTSLIST"            "NOPAGE" "DIRECTORY SYSUAF,RIGHTSLIST"
$ ELSE CALL AuditStep "V$DIR SYS$SYSTEM:SYSUAF.DAT;*,RIGHTSLIST.DAT;*" "" "DIRECTORY SYS$SYSTEM:SYSUAF,RIGHTSLIST"
$ ENDIF
$ !
$ CALL AuditStep "SHOW AUDIT /ALL" "NOPAGE"
$ CALL AuditStep "SHOW ACCOUNTING" "NOPAGE"
$ CALL AuditStep "V$DIR SYS$SYSTEM:LMF$*.LDB" "NOPAGE" "DIRECTORY SYS$SYSTEM:LMF$*.LDB"
$ !
$ ! Special: Review all batch/device/printer/symbiont queues for job-counts exceeding threshold:
$ IF F$TYPE( QUESTALL$THRESHOLD ) .EQS. "" THEN QUESTALL$THRESHOLD == 500
$ CALL AuditStep "@''DD'QUE$STALLED ''QUESTALL$THRESHOLD' TRUE" "" "@''DD'QUE$STALLED ''QUESTALL$THRESHOLD'"
$ !
$ CALL AuditStep "V$AUTH LIST * /BRIEF" "NOPAGE" "AUTH LIST * /BRIEF"
$ CALL AuditStep "V$AUTH LIST * /FULL"  "NOPAGE" "AUTH LIST * /FULL"
$ !
$ ! ========================
$ ! II. System Configuration -- Hardware, Storage, Cluster and Shadowing/Controller
$ CALL AuditStep "SHOW DEVICE D /MOUNTED"
$ !
$ CALL AuditStep "SHOW CPU /FULL"
$ CALL AuditStep "SHOW MEMORY /FULL"
$ !
$ CALL AuditStep "SHOW DEVICE"
$ !
$ CALL AuditStep "V$LANCP SHOW DEVICE"                  ""       "LANCP SHOW DEVICE"
$ CALL AuditStep "V$LANCP SHOW CONFIGURATION"           "NOPAGE" "LANCP SHOW CONFIGURATION"
$ CALL AuditStep "V$LANCP SHOW DEVICE /CHARACTERISTICS" "NOPAGE" "LANCP SHOW DEVICE /CHARACTERISTICS"
$ !
$Dsk0:
$ dsk = F$DEVICE("*","DISK","GENERIC_DK",0)
$ IF ( dsk .EQS. "" ) THEN GOTO Dsk1  ! done...
$ dskL = F$LENGTH(dsk)
$       ! What other disk-types to exclude here???...
$ IF    ( F$LOCATE("DQ",dsk) .GE. dskL ) -   ! not an optical disk (CD,DVD)...
  .AND. ( F$LOCATE("DN",dsk) .GE. dskL )     ! and not a foreign/network disk...
$ THEN IF ( F$GETDVI(dsk,"MNT") )            ! and it's mounted?
$      THEN CALL AuditStep "SHOW DEVICE ''dsk' /FULL" "NOPAGE"
$      ENDIF
$ ENDIF
$ GOTO Dsk0
$Dsk1:
$ !
$ ! ========================
$ ! II.a & b. -- Review of Startup & Shutdown Command Procedures is manual, using a text editor...
$ !
$ ! II.c -- And display the SYSMAN startup/shutdown groups
$ CALL AuditStep "V$SYSMAN STARTUP SHOW FILE /FULL" ""       "SYSMAN STARTUP SHOW FILE /FULL"
$ CALL AuditStep "V$SYSGEN SHOW /STARTUP"           "NOPAGE" "SYSGEN SHOW /STARTUP"
$ CALL AuditStep "V$DIR SYS$STARTUP:SY*.COM;"       "NOPAGE" "DIRECTORY SYS$STARTUP:SY*.COM;""
$ !
$ ! ========================
$ ! III. OpenVMS -- Version & Patch Levels
$ CALL AuditStep "SHOW SYSTEM /HEADER /NOPROCESS"
$ !
$ ! VMS version must be >= v8.4 to auto-drive BOOT_OPTIONS.COM with an Answer File! --
$ IF ( F$GETSYI("ARCH_NAME") .EQS. "IA64" ) .AND. ( VMSver .GES. "v8.4" )
$ THEN ! Answer-file: B 2 (display boot options), D 2 (display device options), E (exit) --
$      AnsFile = "VMS$AUDIT_BOOT_OPTIONS.ANSWERS"
$      CALL AuditStep "@SYS$MANAGER:BOOT_OPTIONS ''Dev'''Dir'''AnsFile'" -
         "NOPAGE" "@BOOT_OPTIONS ''AnsFile'"
$ ENDIF
$ !
$ ! ========================
$ ! IV. Product Review -- Layered Product Licensing, versions/patches
$ CALL AuditStep "V$DIR SYS$SYSTEM:LMF$*.LDB" "" "DIRECTORY SYS$SYSTEM:LMF$*.LDB"
$ CALL AuditStep "SHOW LICENSE" "NOPAGE"
$ CALL AuditStep "SHOW LICENSE /USAGE"
$ CALL AuditStep "PRODUCT SHOW PRODUCT /FULL"
$ CALL AuditStep "PRODUCT SHOW HISTORY /FULL"
$ CALL AuditStep "TYPE SYS$UPDATE:VMSINSTAL.HISTORY"
$ !
$ ! IV.d. Application Review -- manual audit, conversations with on-site dev/user/mgmt team
$ !
$ CALL AuditStep "SHOW QUEUE /FULL *"
$ !
$ ! ========================
$ !
$ ! V. Backup -- manual audit, conversations with on-site dev/mgmt team
$ !
$ ! ========================
$ !
$ ! VI.b. & k. Security -- Audit and Accounting Files
$ CALL AuditStep "SHOW AUDIT /ALL"
$ CALL AuditStep "V$DIR SYS$MANAGER:SECURITY*.AUDIT$JOURNAL;*" "NOPAGE" "DIRECTORY SYS$MANAGER:SECURITY*.AUDIT$JOURNAL;*"
$ !
$ ! VI.c. & j. Security -- Accounting
$ CALL AuditStep "SHOW ACCOUNTING"
$ CALL AuditStep "V$DIR SYS$MANAGER:ACCOUNTNG*.DAT;*" "NOPAGE" "DIRECTORY SYS$MANAGER:ACCOUNTNG*.DAT;*"
$ !
$ ! VI.d. Other System (parameters)
$ CALL AuditStep "V$SYSGEN SHOW /SYS"           ""       "SYSGEN SHOW /SYS"
$ CALL AuditStep "V$SYSGEN SHOW /CLUSTER"       "NOPAGE" "SYSGEN SHOW /CLUSTER"
$ CALL AuditStep "V$SYSGEN SHOW SCS*"           "NOPAGE" "SYSGEN SHOW SCS*"
$ CALL AuditStep "V$SYSGEN SHOW /MAJOR"         "NOPAGE" "SYSGEN SHOW /MAJOR"
$ CALL AuditStep "V$SYSGEN SHOW NISCS*"         "NOPAGE" "SYSGEN SHOW NISCS*"
$ CALL AuditStep "V$SYSGEN SHOW LGI*"           ""       "SYSGEN SHOW LGI*"   ! "/LGI" gets an extra <FF> in wrong place...
$ CALL AuditStep "V$SYSGEN SHOW RMS*"           "NOPAGE" "SYSGEN SHOW RMS*"
$ CALL AuditStep "V$SYSGEN SHOW UAFALTERNATE"   "NOPAGE" "SYSGEN SHOW UAFALTERNATE"
$ !
$ ! VI.e. & f. Facility and Policy Audits -- manual audit, conversations with on-site team
$ !
$ ! VI.h. ACL Utilization -- manual audit, conversations with on-site team
$ !
$ ! VI.i. System Disk Protection
$ Call AuditStep "SHOW DEVICE sys$sysdevice /FULL"
$ !
$ ! ========================
$ !
$ ! VII. Network
$ CALL AuditStep "SHOW NETWORK"
$ !
$!! $ wserr ""
$!! $ READ sys$command Answer /END_OF_FILE=Done -
$!!     /PROMPT="Perform TCP/IP Audit Steps (is TCP/IP networking installed & configured) [Y/n]? "
$!! $ Answer = F$PARSE(Answer,"Yes",,"NAME","SYNTAX_ONLY")
$!! $ IF Answer
$ IF VA$TCPIPInst
$ THEN ! VII.a. & c. Network -- IP & DNS (BIND) Configurations
$      CALL AuditStep "TCPIP SHOW VERSION"
$      CALL AuditStep "TCPIP SHOW CONFIGURATION NAME_SERVICE"           "NOPAGE" "BIND (DNS) Configuration"
$      CALL AuditStep "TCPIP SHOW NAME_SERVICE"                         "NOPAGE"
$      CALL AuditStep "TCPIP SHOW CONFIGURATION COMMUNICATION"          "NOPAGE"
$      CALL AuditStep "TCPIP SHOW COMMUNICATION"                        "NOPAGE"
$      CALL AuditStep "TCPIP SHOW CONFIGURATION ENABLE SERVICE"         "NOPAGE"
$      CALL AuditStep "TCPIP SHOW CONFIGURATION ENABLE SERVICE /COMMON" "NOPAGE"
$      CALL AuditStep "TCPIP SHOW SERVICE /FULL /PERMANENT"             "NOPAGE"
$      CALL AuditStep "TCPIP SHOW SERVICE /FULL"                        "NOPAGE"
$      CALL AuditStep "TCPIP SHOW INTERFACE"                            "NOPAGE"
$      CALL AuditStep "V$IFCONFIG -a"                                   "NOPAGE" "IFCONFIG -a"
$      CALL AuditStep "TCPIP SHOW HOST /LOCAL"                          "NOPAGE"
$      CALL AuditStep "TCPIP SHOW ROUTE /PERMANENT"                     "NOPAGE"
$      CALL AuditStep "TCPIP SHOW ROUTE"                                "NOPAGE"
$      CALL AuditStep "TCPIP SHOW PROXY /PERMANENT"                     "NOPAGE"
$      CALL AuditStep "SHOW LOGICAL /SYSTEM /FULL TCPIP$*"              "NOPAGE"
$ ENDIF
$ !
$!! $ wserr ""
$!! $ READ sys$command Answer /END_OF_FILE=Done -
$!!     /PROMPT="Perform DECnet Audit Steps (is DECnet networking installed & configured) [Y/n]? "
$!! $ Answer = F$PARSE(Answer,"Yes",,"NAME","SYNTAX_ONLY")
$!! $ IF Answer
$ IF VA$DECnetInst
$ THEN ! VII.b. Network -- DECnet Configuration
$      DECnetVers = F$GETSYI("DECNET_VERSION")
$      dnv        = F$INTEGER(DECnetVers)
$      dnvstr     = F$EXTRACT(3,1,DECnetVers) + "." + F$EXTRACT(4,2,DECnetVers)
$      VA$DECnet  == F$FAO( "DECnet for OpenVMS Version !AS", dnvstr )
$      CALL AuditStep "WRITE sys$output VA$DECnet"  "" "''VA$DECnet'"
$      IF ( dnv .GE. 50000 ) THEN GOTO PhaseV
$PhaseIV:
$      CALL AuditStep "V$NCP SHOW EXECUTOR CHARACTERISTICS" "NOPAGE" "NCP SHOW EXECUTOR CHARACTERISTICS"
$      CALL AuditStep "V$NCP SHOW KNOWN NODES"              "NOPAGE" "NCP SHOW KNOWN NODES"
$      CALL AuditStep "V$NCP LIST KNOWN NODES"              "NOPAGE" "NCP LIST KNOWN NODES"
$      CALL AuditStep "V$NCP SHOW KNOWN OBJECTS"            "NOPAGE" "NCP SHOW KNOWN OBJECTS"
$      CALL AuditStep "V$NCP LIST KNOWN OBJECTS"            "NOPAGE" "NCP LIST KNOWN OBJECTS"
$      GOTO DNDone
$PhaseV:
$      CALL AuditStep "V$NCL SHOW NODE 0 ROUTING CIRCUIT CSMACD-0 ADJACENCY * ALL STATUS" -
                        "NOPAGE" "NCL SHOW NODE 0 ROUTING CIRCUIT CSMACD-0 ADJACENCY * ALL STATUS"
$      CALL AuditStep "V$NCL SHOW ROUTING CIRCUIT CSMACD-0 ALL"       "NOPAGE" "NCL SHOW ROUTING CIRCUIT CSMACD-0 ALL"
$      CALL AuditStep "V$NCL SHOW ALL IDENTIFIERS"                    "NOPAGE" "NCL SHOW ALL IDENTIFIERS"
$      CALL AuditStep "V$NCL SHOW SESSION CONTROL ALL STATUS"         "NOPAGE" "NCL SHOW SESSION CONTROL ALL STATUS"
$      CALL AuditStep "V$NCL SHOW ROUTING ALL CHARACTERISTICS"        "NOPAGE" "NCL SHOW ROUTING ALL CHARACTERISTICS"
$      CALL AuditStep "V$NCL SHOW SESSION CONTROL APPLICATION * NAME" "NOPAGE" "NCL SHOW SESSION CONTROL APPLICATION * NAME"
$DNDone:
$      CONTINUE
$ ENDIF
$ !
$ IF VA$MultinetInst
$ THEN ! VII.b. Network -- Multinet Configuration
$      ! �� CALL AuditStep "V$MNET SHOW ��" "��" "MULTINET SHOW ��"
$ ENDIF
$ !
$ ! VII.d. & e. Security Policy & Network Topology (printout)) -- manual audit, conversations with on-site network team
$ !
$ ! ========================
$ !
$ ! VIII.a. Other: Monitoring Utilities -- manual audit, conversations with on-site network team
$ !
$ ! ========================
$ !
$ ! Done...
$ CALL TimeStamp ""   ! global VA$TimeStamp
$ CALL ReportFooter "''Fac'" "''Node'" "''VA$TimeStamp'"
$ !
$ ! ...and fall-through to Clean-up Report:
$ !
$ !
$ ! ========================
$ !
$CLE$:
$ ! Convert embedded <CR><LF> to new-lines, then trim-trailing...
$ IF OutToFile
$ THEN DEASSIGN /NOLOG /PROCESS sys$output
$      CleanCRLF = "REPLACECRLF"
$      CleanTrim = "TRIMTRAIL"
$      fsCRLF    = F$PARSE("''Fac'_''CleanCRLF'","''DD'.TPU",,,"SYNTAX_ONLY")
$      fsTrim    = F$PARSE("''Fac'_''CleanTrim'","''DD'.TPU",,,"SYNTAX_ONLY")
$      IF ( F$SEARCH(fsTrim) .EQS. "" ) .OR. ( F$SEARCH(fsCRLF) .EQS. "" )
$      THEN msg = "%!AS-E-FNF, missing one or both report cleaning components:!/" -
                + "!#* !AS &/or !AS"
$           wserr F$FAO( msg, Fac, 18, CleanTrim, CleanCRLF )
$           GOTO Done
$      ELSE ! <CR><LF> -> newlines first, then trim trailing...
$           CALL Cleaner "''VA$AuditReport'" "''CleanCRLF'" "''fsCRLF'"
$           CALL Cleaner "''VA$AuditReport'" "''CleanTrim'" "''fsTrim'"
$      ENDIF
$ ENDIF
$ ! ...and fall-through to Review:
$ !
$ ! ========================
$ !
$REV$:   ! Review the Audit Report File
$ IF OutToFile
$ THEN DEASSIGN /NOLOG /PROCESS sys$output
$      wso ""
$      Rfile = F$PARSE(VA$AuditReport,,,"NAME","SYNTAX_ONLY") + F$PARSE(VA$AuditReport,,,"TYPE","SYNTAX_ONLY")
$      READ sys$command Answer /END_OF_FILE=Done -
         /PROMPT="''Rfile' -- Type it or Edit it [T/e]? "
$      Answer = F$PARSE(Answer,"TYPE",,"NAME","SYNTAX_ONLY")
$      GOTO 'F$EXTRACT(0,1,Answer)'$
$ !
$T$:    ! Type/display Audit Report File
$TYP$:
$      IF OutToFile THEN DEASSIGN /NOLOG /PROCESS sys$output
$      DEFINE /USER_MODE sys$input sys$command
$      TYPE /PAGE=SAVE=5 'VA$AuditReport'
$      GOTO Done
$ !
$E$:    ! Edit Audit Report File
$EDI$:
$      IF OutToFile THEN DEASSIGN /NOLOG /PROCESS sys$output
$      IF F$TYPE(ked) .EQS. "STRING" THEN edit = "@com:ked.com"  !(LMR tweak, all others use EDIT /EVE)
$      DEFINE /USER_MODE sys$input sys$command
$      EDIT 'VA$AuditReport'
$      GOTO Done
$ !
$ ELSE GOTO Done
$ ENDIF
$ !
$ !
$ ! ========================
$ !
$BAC$:
$ BACKUP /LIST='V$BckSSN' /NOCRC /GROUP_SIZE=0 /INTERCHANGE -
    'V$BckList' 'V$BckSSN'.BCK /SAVE_SET
$ TYPE 'V$BckSSN'.LIS
$ PURGE /NOLOG 'V$BckSSN'.BCK,.LIS
$ DIRECTORY /SIZE /DATE /PROT 'V$BckSSN'
$ GOTO Done
$ !
$RES$:
$ V$BckSSN = V$BckSSN + ".BCK"
$ IF ( F$SEARCH("''V$BckSSN'") .NES. "" )
$ THEN BACKUP /LOG 'V$BckSSN' /SAVE_SET []*.* /NEW_VERSION
$ ELSE WRITE sys$error F$FAO( "%!AS-E-FNF, cannot find file !AS", V$BckSSN )
$ ENDIF
$ GOTO Done
$ !
$ ! ========================
$ !
$ZIP$:    ! Zip the VMS$AUDIT files into the archive 'V$ZipArc'
$ IF F$TYPE(zip) .NES. "STRING"
$ THEN DEFINE /PROCESS /NOLOG ZDIR 'DD',SYS$SYSTEM
$      zipexe = F$SEARCH("ZDIR:ZIP.EXE")
$      IF ( zipexe .NES. "" )
$      THEN zip == "$''zipexe'"
$           GOTO GoodZip
$      ELSE wserr F$FAO( "%!AS-E-FNF, zip utility !AS is not available", Fac, "ZIP.EXE" )
$           GOTO Done
$      ENDIF
$ ELSE GOTO GoodZip
$ ENDIF
$GoodZip:
$ IF ( F$SEARCH(V$ZipArc) .NES. "" ) THEN RENAME 'V$ZipArc' 'V$ZipArc'_OLD
$ zip -v 'V$ZipArc' 'V$ZipList'
$ IF ( F$SEARCH("''V$ZipArc'_OLD;-1") .NES. "" ) THEN PURGE /NOLOG 'V$ZipArc'_OLD
$ GOTO Done
$ !
$UNZ$:    ! UnZip the archive 'V$ZipArc' into the current directory
$ IF F$TYPE(unzip) .NES. "STRING"
$ THEN DEFINE /PROCESS /NOLOG ZDIR 'DD',SYS$SYSTEM
$      unzipexe = F$SEARCH("ZDIR:UNZIP.EXE")
$      IF ( unzipexe .NES. "" )
$      THEN unzip == "$''unzipexe'"
$           GOTO GoodUnZip
$      ELSE wserr F$FAO( "%!AS-E-FNF, unzip utility !AS is not available", Fac, "UNZIP.EXE" )
$           GOTO Done
$      ENDIF
$ ELSE GOTO GoodUnZip
$ ENDIF
$GoodUnZip:
$ DEFINE /USER_MODE sys$input sys$command   ! unzip goes interactive...
$ unzip 'V$ZipArc'
$ GOTO Done
$ !
$ ! ========================
$ !
$Done:
$ SET NOON
$ IF OutToFile THEN DEASSIGN /NOLOG /PROCESS sys$output
$ IF F$TYPE(prv)             .NES. "" THEN prv = F$SETPRV(prv)
$ IF F$TYPE(VA$DECnetInst)   .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$DECnetInst
$ IF F$TYPE(VA$TCPIPInst)    .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$TCPIPInst
$ IF F$TYPE(VA$MultinetInst) .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$MultinetInst
$ IF F$TYPE(VA$PgNo)         .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$PgNo
$ IF F$TYPE(VA$PgWi)         .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$PgWi
$ IF F$TYPE(VA$PgStr)        .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$PgStr
$ IF F$TYPE(VA$TimeStamp)    .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$TimeStamp
$ IF F$TYPE(VA$DECnet)       .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$DECnet
$ IF F$TYPE(VA$Dashes)       .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$Dashes
$ IF F$TYPE(VA$DblDashes)    .NES. "" THEN DELETE /SYMBOL /GLOBAL VA$DblDashes
$ ! Note: Do *not* delete global symbol VA$AuditReport --
$ !       once defined, used as a user-login convenience.
$ EXIT
$ !
$Ctrl_Y:
$ RETURN %X2C
$ !
$ !
$ ! ========================
$ !
$H$:
$HEL$:
$ TYPE /PAGE sys$input

  [1mVMS$AUDIT.COM[0m is an Audit Report Generator for VMS (OpenVMS).  It provides
  convenient reporting consistency when auditing multiple systems and sites,
  generating a standardized, paginated and labeled report format for review
  and analysis.
  
  This command procedure provides the following functions:
  
  a) Generate an Audit Report, either to file or to the user's terminal.
  b) Review an Audit Report, using either the TYPE /PAGE facility or the
     user's favorite text editor (EVE, KED, etc.).

  [4mInstallation[0m: This is a very compact suite of files, with no "software
  to install" (e.g., PRODUCT or VMSINSTAL).  The files are: VMS$AUDIT.COM
  (this command file), QUE$STALLED.COM (checks VMS queues for job-counts in
  excess of a threshold), VMS$AUDIT_{REPLACECRLF,TRIMTRAIL}.TPU (the two TPU
  cleanup scripts), and VMS$AUDIT_BOOT_OPTIONS.ANSWERS (a text-answer file).

  For convenience, these four files are zipped into an archive, VMS$AUDIT.ZIP,
  which can be FTP'd (scp, etc.) and unzipped into any appropriate directory
  on a target VMS system.  Other than the actual Audit Report File(s), VMS$AUDIT
  leaves no file-litter (temp-files) behind, and the Report File itself is
  created by default into the directory from which VMS$AUDIT is run (invoked).
  Self-contained and tidy.

  [4mUse[0m: The user must either be logged-in as SYSTEM, or have the following
  privileges authorized for his/her account: SETPRV, or SYSNAM, SYSPRV,
  SECURITY, CMKRNL, BYPASS, VOLPRO and OPER.

  When generating an Audit Report, the user is prompted for the Report's
  filename; a default of the form VMS$AUDIT_<nodename>.REPORT is offered.
  Alternatively, the Report may be displayed directly on-screen (in this
  case, no Report File is saved), which is useful for quick-checks or
  debugging the command file itself.
  
  In both instances, the user is also prompted for his/her actual name,
  which appears in the Report's header for accountability purposes.

  use: $ [1m@VMS$AUDIT [ AUDIT (D) | GENERATE (D)
                      | REVIEW | TYPE | EDIT | CLEANUP
                      | BACKUP | RESTORE | ZIP | UNZIP | HELP ][0m

  where:
  
        [1mAUDIT[0m    -- Both of these keywords generate a new Audit Report
        [1mGENERATE[0m    which is also the default operation (no keyword)
                    specified.

        [1mREVIEW[0m   -- Prompts the user for the method to use in reviewing
                    the current Audit Report File, either TYPE /PAGE or
                    text editor.  The default ("T") is to use TYPE.

        [1mTYPE[0m     -- Reviews the current Audit Report File using the
                    DCL TYPE /PAGE command, allowing you to scroll
                    back and forward several pages at a time.

        [1mEDIT[0m     -- Reviews the current Audit Report File using your
                    favorite VMS text editor (e.g., EVE, KED, etc.).
                    Note that the file is opened in RW mode, so you
                    can indeed modify the Report if you want; change
                    the editor's file buffer mode to RO (read only),
                    and/or exit correctly if you don't want to change
                    the file accidentally.

        [1mCLEANUP[0m  -- Certain of the system administration DCL commands
                    used to generate the Audit Report File embed literal
                    <CR><LF> and trailing-space characters, which can be
                    confuse the display when the Report is opened in a
                    text editor.  This CLEANUP step uses two TPU command
                    scripts, REPLACECRLF and TRIMTRAIL, to replace any
                    <CR><LF> characters with a newline(s) and to trim
                    any trailing spaces from all lines.  This step is
                    idempotent (can be run multiple times).

        [1mBACKUP[0m      Backup and restore will save all VMS$AUDIT suite file
        [1mRESTORE[0m     components into/from a saveset called VMS$AUDIT.BCK.

        [1mZIP[0m         If the (unsupported) utilities ZIP.EXE and UNZIP.EXE are
        [1mUNZIP[0m       available on the system (usually found in SYS$SYSTEM),
                    these command options will zip/unzip all VMS$AUDIT file
                    components into a VMS$AUDIT.ZIP archive into/from the
                    current directory.

        [1mHELP[0m     -- Displays this help text.
        
$ GOTO Done
$ !