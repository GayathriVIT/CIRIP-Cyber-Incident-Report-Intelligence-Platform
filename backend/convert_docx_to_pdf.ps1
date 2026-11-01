$docxPath = Resolve-Path "CIRIP_Project_Report_v4.docx"
$pdfPath = [System.IO.Path]::ChangeExtension($docxPath, ".pdf")

Write-Host "Converting $docxPath to $pdfPath..."
$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open($docxPath.Path)
    # 17 represents wdFormatPDF
    $doc.SaveAs([ref]$pdfPath, [ref]17)
    $doc.Close()
    Write-Host "PDF export completed successfully!"
} catch {
    Write-Host "Error during PDF export:" $_.Exception.Message
} finally {
    $word.Quit()
}
