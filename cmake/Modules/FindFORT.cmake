#
# Try to find libfort.
#

# Try to find the header
find_path(FORT_INCLUDE_DIR fort.h)

# Try to find the library
find_library(FORT_LIBRARY fort)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(fort
  DEFAULT_MSG
  FORT_INCLUDE_DIR
  FORT_LIBRARY
)

mark_as_advanced(
  FORT_INCLUDE_DIR
  FORT_LIBRARY
)

set(FORT_INCLUDE_DIRS ${FORT_INCLUDE_DIR})
set(FORT_LIBRARIES ${FORT_LIBRARY})