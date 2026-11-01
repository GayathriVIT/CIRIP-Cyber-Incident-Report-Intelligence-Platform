$word = New-Object -ComObject Word.Application
try {
    foreach ($item in $word.RecentFiles) {
        Write-Host $item.Path "\" $item.Name
    }
} finally {
    $word.Quit()
}
