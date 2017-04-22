        <center>
<body>

<div class="container">
    <h1>Editar</h1>
    <h4><a href="<?php echo e(route('comentarios.index')); ?>">Comentarios</a></h4>
    <hr>

    <form method="comen" action="/comentarios/<?php echo e($comentario->id); ?>" enctype="multipart/form-data">>
        <input name="_method" type="hidden" value="PUT">
        <?php echo $__env->make('post.form', array_except(get_defined_vars(), array('__data', '__path')))->render(); ?>
        <button type="submit" class="btn btn-success">Actualizar</button>
    </form>
</div>


</body>
</center>
</html>

<?php echo $__env->make('layouts.app', array_except(get_defined_vars(), array('__data', '__path')))->render(); ?>