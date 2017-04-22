<body>
<div class="container">
    <h1>Temas</h1>
      <?php if(!Auth::guest()): ?>
    <h4><a href="<?php echo e(route('posts.create')); ?>">Crear Aviso</a></h4>
    <hr>
    <?php endif; ?>

    <div class="table-responsive">
        <?php if($data): ?>
          
                <?php $__currentLoopData = $data; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $row): $__env->incrementLoopIndices(); $loop = $__env->getFirstLoop(); ?>
                    <tr>
                    <lavel><img src="image/<?php echo e($row->image); ?>"style="width:300px;"/>
                    <img src="image/<?php echo e($row->image2); ?>"style="width:300px;"/></lavel>
                         <h3>Nombre</h3>
                        <label><?php echo e($row->name); ?></label>
                        <h3>Titulo</h3>
                        <label><?php echo e($row->title); ?></label>
                        <h3>contenido</h3>
                        <label><?php echo e($row->body); ?></label>
                        <p>creado</p>
                        <label><?php echo e($row->created_at); ?></label>
                         
                         <ol><label><a href="<?php echo e(route('comentarios.index')); ?>">comentarios</a></label></ol>
                         </tr>
      <a href="<?php echo e(route('posts.edit', $row->id)); ?>" class="btn btn-info">Editar</a>
                               <form action="<?php echo e(route('posts.destroy', $row->id)); ?>" method="post">
                                <input name="_method" type="hidden" value="DELETE">
                                <input type="hidden" name="_token" value="<?php echo e(csrf_token()); ?>">
                                <button type="submit" class="btn btn-danger">Eliminar</button>
                                 </form>
                                 </td>
                    </tr>
                </tbody>
                <?php endforeach; $__env->popLoop(); $loop = $__env->getFirstLoop(); ?>
            </table>
               <?php endif; ?>

</div>

 



</body>

<?php echo $__env->make('layouts.app', array_except(get_defined_vars(), array('__data', '__path')))->render(); ?>