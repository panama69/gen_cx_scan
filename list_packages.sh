Example which was used to extract package names and their corresponding paths from a Syft scan of the 
`sasanlabs/owasp-vulnerableapp:latest` image. 
The command filters for artifacts located in the `/app/libs/` directory, attempts to determine the groupId 
from the POM properties or PURL namespace, and outputs the package name along with its path. 
The results are sorted and made unique.

syft scan sasanlabs/owasp-vulnerableapp:latest -o json | jq -r '.artifacts[] | 
  select(.locations[].path | startswith("/app/libs/")) | 
  # Fallback chain: Check pom properties, then try extracting from PURL namespace
  (.metadata.pomProperties.groupId // (if .purl then (.purl | split("?")[0] | split("/")[1] | select(. != null)) else null end)) as $groupId |
  .name as $name |
  # Process each location isolated to prevent path cross-contamination
  .locations[] | select(.path | startswith("/app/libs/")) | 
  if $groupId then "\($groupId):\($name) -> \(.path)" else "\($name) -> \(.path)" end' | sort -u