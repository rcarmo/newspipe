<script language="php">
require( "main.php");

if( $gszUid ) {
  if( $gszParam == "" ) {
    @$gaValues = array_merge( $gaValues, $goIMAP->getMessage($gszUid) );
    header('Content-Type: text/html; charset=utf-8');
    $oTemplate = new CTemplate( "message.html" );
    echo $oTemplate->replaceValues( $gaValues );
  }
  else {
    list( $type, $length, $content ) = $goIMAP->getNamedPart( $gszUid, $gszParam );
    header( "Content-Length: " . $length);
    header( "Content-Type: " . $type );
    echo $content;
  }
}
</script>
