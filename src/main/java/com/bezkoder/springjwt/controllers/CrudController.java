package com.bezkoder.springjwt.controllers;

        import com.bezkoder.springjwt.models.User;
        import com.bezkoder.springjwt.security.services.CrudService;
        import org.slf4j.Logger;
        import org.slf4j.LoggerFactory;
        import org.springframework.beans.factory.annotation.Autowired;
        import org.springframework.security.access.prepost.PreAuthorize;
        import org.springframework.web.bind.annotation.*;

        import java.util.List;

@RestController
@RequestMapping("/users")
public class CrudController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    @Autowired
    private CrudService crudService;


    // µµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµ

    @PreAuthorize("hasRole('ROLE_USER') or hasRole('MODERATOR') or hasRole('ROLE_ADMIN')")
    @GetMapping("/afficher")
    public  List<User> AfficherUsers(){
        log.info("Affichage de la liste des Collaborateurs ");

        return crudService.Afficher();
    }

    // µµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµ   MODIFIER
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PutMapping({"/modifier"})
    public String ModierUser(@RequestBody User users){
        log.info("Collaborateur "+users.getUsername() + " modifié avec succès");
        crudService.Modifier(users);
        return "Modification reussie avec succès";
    }


    @DeleteMapping("/Supprimer/{id_users}")
    @PreAuthorize("hasRole('ADMIN')")
    public String Supprimer(@PathVariable("id_users") Long id_users){
        log.info("Collaborateur supprimé avec succès");

        crudService.Supprimer(id_users);
        return "Suppression reussie";
    }




}