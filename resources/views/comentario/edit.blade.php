@extends('layouts.app')
        <center>
<body>

<div class="container">
    <h1>Editar</h1>
    <h4><a href="{{ route('comentarios.index') }}">Comentarios</a></h4>
    <hr>

    <form method="comen" action="/comentarios/{{ $comentario->id }}" enctype="multipart/form-data">>
        <input name="_method" type="hidden" value="PUT">
        @include('post.form')
        <button type="submit" class="btn btn-success">Actualizar</button>
    </form>
</div>


</body>
</center>
</html>
