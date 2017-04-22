        <center>
<body>

<div class="container">
    <h1>Aviso nuevo</h1>
    <h4><a href="<?php echo e(route('posts.index')); ?>">Lista de avisos</a></h4>
    <hr>

    <form method="post" action="/posts" id="Com" enctype="multipart/form-data"> >
        <?php echo $__env->make('post.form', array_except(get_defined_vars(), array('__data', '__path')))->render(); ?>
        
         <button type="submit" class="btn btn-primary">Enviar</button>
    </form>
</div>


</body>
</center>
</html>

<?php echo $__env->make('layouts.app', array_except(get_defined_vars(), array('__data', '__path')))->render(); ?>