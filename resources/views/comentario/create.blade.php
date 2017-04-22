@extends('layouts.app')
        <center>
<body>

<div class="container">
    <h1>nuevo comentario</h1>
    <h4><a href="{{ route('comentarios.index') }}">comentarios</a></h4>
    <hr>

    <form method="comen" action="/comentarios" id="Com" enctype="multipart/form-data"> >
        @include('comentario.form')
        
         <button type="submit" class="btn btn-primary">Enviar</button>
    </form>
</div>


</body>
</center>
</html>
