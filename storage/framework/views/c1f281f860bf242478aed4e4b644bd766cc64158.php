<?php $__env->startSection('content'); ?>
<div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">  ¡Bivenido!</div>

                <div class="panel-body">
                    Este sitio web está enfocado en el registro de personas desaparecidas con la finalidad de poder brindar información para poder encontrarlas. 

                   <div>

                    <div class="panel-body">
                    Reglas
<br>1.-cada uno de los avisos, debe contener dos foto de la persona que se busca con la finalidad de tener mayor informacion del aspecto de este.
<br>2.-Cada aviso tiene que tener un medio de contacto(Email, Facebook, número de teléfono. Etc.)
<br>3.-Los avisos son y deben ser únicamente relacionados a las personas desaparecidas todo lo que este fuera de esto será borrado.
<br>4.-Los avisos deben contener el nombre completo del desaparecido.

                    </div>
                    <?php if(!Auth::guest()): ?>
                        <h4><a href="<?php echo e(route('posts.index')); ?>">ver avisos</a></h4>
                         <?php endif; ?>

                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.app', array_except(get_defined_vars(), array('__data', '__path')))->render(); ?>