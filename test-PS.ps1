
function Get-FileInfo($userInput) {

    $cmd = "Get-ChildItem " + $userInput
    Invoke-Expression $cmd
}

Get-FileInfo $args[0]
