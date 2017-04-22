@extends('layouts.app')
        <center>
<body>

<div class="container">
    <h1>Aviso nuevo</h1>
    <h4><a href="{{ route('posts.index') }}">Lista de avisos</a></h4>
    <hr>

    <form method="post" action="/posts" id="Com" enctype="multipart/form-data"> >
        @include('post.form')
        
         <button type="submit" class="btn btn-primary">Enviar</button>
    </form>
</div>


</body>
</center>
</html>
