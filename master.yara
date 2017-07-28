
// utility rules
include "utility/IsPeFile.yara"
include "utility/IsElfFile.yara"
include "utility/IsZipFile.yara"

// family or campaign specific signatures
include "alphacrypt.yara"
include "appraisel.yara"
include "billgates.yara"
include "conbot.yara"
//include "emotet.yara"
include "ggupdate.yara"
include "granite_coroner.yara"
include "hawkeye.yara"
include "l_exe.yara"
include "libgcc.yara"
include "mimikatz.yara"
include "regin.yara"
include "scrtest.yara"
include "sqldb.yara"
include "turla.yara"
include "viewweb.yara"
include "wiper.yara"

// packer-related signatures
include "packers/aspack.yara"
include "packers/nkh.yara"
include "packers/rlpack.yara"
include "packers/sogu_packer.yara"
include "packers/upx.yara"
include "packers/vmprotect.yara"

// feature identification signatures
include "features/command_shell.yara"
include "features/virtualbox_detection.yara"
