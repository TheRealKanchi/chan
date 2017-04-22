<body>

<div class="container">
    <h1>comentarios</h1>
     
    <h4><a href="<?php echo e(route('comentarios.create')); ?>">comentar</a></h4>
    <hr>
    <label><a href="<?php echo e(route('posts.index')); ?>">regresar a los avisos</a></label></h3>



    <div class="table-responsive">
        <?php if($cont): ?>
          
                <?php $__currentLoopData = $cont; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $row): $__env->incrementLoopIndices(); $loop = $__env->getFirstLoop(); ?>
                    <tr>
                        <h3>comentario</h3>
                        <label><?php echo e($row->comen); ?></label>
                        <p>comentado</p>
                        <label><?php echo e($row->created_at); ?></label>
                        
                        
                        <td>
                         <a href="<?php echo e(route('comentarios.edit', $row->id)); ?>" class="btn btn-info">Editar</a>
                               <form action="<?php echo e(route('comentarios.destroy', $row->id)); ?>" method="post">
                                <input name="_method" type="hidden" value="DELETE">
                                <input type="hidden" name="_token" value="<?php echo e(csrf_token()); ?>">
                                <button type="submit" class="btn btn-danger">Eliminar</button>
                                 </form>

                                 <h3>
                        
                        </td>
                    </tr>
                </tbody>
                <?php endforeach; $__env->popLoop(); $loop = $__env->getFirstLoop(); ?>
            </table>
               <?php endif; ?>

               
    </div>
</div>


</body>
 
</html>
<?php echo $__env->make('layouts.app', array_except(get_defined_vars(), array('__data', '__path')))->render(); ?>