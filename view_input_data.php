/* Visualisation des données récupéré par les capteurs

<!--
In this file we can see all the data collected by the sensors and put into the database, in addition to add some data of moisture and temperature if necessary.
-->

<html>
<head>
   <title>Data of Sensor</title>
</head>
<body>
<h1>Data from the temperature and moisture sensors</h1>
<form action="Adding_data.php" method="get">
<TABLE>
<tr>
   <td>Temperature</td>
   <td><input type="text" name="temp" size="20" maxlength="30"></td>
</tr>
<tr>
   <td>Light</td>
   <td><input type="text" name="light" size="20" maxlength="30"></td>
</tr>
<tr>
   <td>Sound</td>
   <td><input type="text" name="sound" size="20" maxlength="30"></td>
</tr>
</TABLE>
<input type="submit" name="accion" value="Grabar">
</FORM>
<hr>
<?php
   include("connexion.php");
   $link=connection();
   $result=mysql_query("select * from temp order by id desc",$link);
?>
<table border="1" cellspacing="1" cellpadding="1">
      <tr>
         <td>&nbsp;Temperature&nbsp;</td>
         <td>&nbsp;Light&nbsp;</td>
         <td>&nbsp;Sound&nbsp;</td>
       </tr>
<?php     
   while($row = mysql_fetch_array($result)) {
printf("<tr><td> &nbsp;%s </td><td> &nbsp;%s&nbsp; </td></tr>", $row["temp1"], $row["moi1"]);
   }
   mysql_free_result($result);
?>
</table>
</body>
</html>

