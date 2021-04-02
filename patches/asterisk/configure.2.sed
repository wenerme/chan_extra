    GSMAT_DESCRIP="GSMAT"
    GSMAT_OPTION="gsmat"
    PBX_GSMAT=0

# Check whether --with-gsmat was given.
if test "${with_gsmat+set}" = set; then
  withval=$with_gsmat;
	case ${withval} in
	n|no)
	USE_GSMAT=no
	;;
	y|ye|yes)
	ac_mandatory_list="${ac_mandatory_list} GSMAT"
	;;
	*)
	GSMAT_DIR="${withval}"
	ac_mandatory_list="${ac_mandatory_list} GSMAT"
	;;
	esac

fi









 