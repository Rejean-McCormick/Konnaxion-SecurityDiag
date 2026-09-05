param(
    [Parameter(Position=0)]
    [string]$Campaign = "repo"
)
$ToolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
& python (Join-Path $ToolRoot "securitydiag.py") run $Campaign
exit $LASTEXITCODE
