# angular-jwt-tutorial
Tutorial sobre Angular + JWT (Adaptación de https://www.positronx.io/angular-jwt-user-authentication-tutorial/) 

## Introducción
En este tutorial vamos a crear un sistema de autenticación de usuario en Angular utilizando JSON Web Token (JWT). Generalmente, el desarrollo de una aplicación se realiza por partes, agregando una funcionalidad a la vez. En un proyecto real, no seguiremos el mismo orden que se dispone en el tutorial, pero por razones de claridad y brevedad, realizaremos el proceso trabajando en un archivo a la vez hasta completar el contenido de esa clase (dado que conocemos de antemano la totalidad de lo que queremos implementar y cómo vamos a hacerlo).

Como Back End para el sistema de autenticación de usuario, clonaremos una API RESTful sencilla desarrollada utilizando node, express y mongoDB (quienes estén interesados en cómo realizarla pueden visitar [este tutorial](https://www.positronx.io/build-secure-jwt-token-based-authentication-api-with-node/)).

## ¿Qué es JWT (token web JSON)?

JWT se refiere a JSON Web Token. Es un token en forma de string validado y generado por un servidor web. Podmeos utilizar este token para transferir los datos de forma segura entre el cliente y el servidor, implementando un flujo que funcione de la siguiente manera:
1. La información del usuario (nombre de usuario y contraseña) se envía al servidor mediante una solicitud HTTP POST al servidor web.
2. El servidor web valida la información del usuario, crea un token y lo envía de regreso al cliente.
3. El cliente almacena ese token en el almacenamiento local o en una sesión y, en las próximas llamadas HTTP, lo agrega en el encabezado (headers).
4. El servidor verifica que el token sea válido y devuelve la respuesta al cliente.

## Ejemplo de autenticación de usuario utilizando Angular y JWT

Se pretende realizar un proyecto que cumpla con los siguientes requisitos:
- El usuario debe poder iniciar sesión
- El usuario debe poder registrarse
- Ocultar/mostrar elementos del menú según el estado de autenticación
- Restringir el acceso del usuario a la página de perfil de usuario cuando el usuario no haya iniciado sesión.
- Almacenar el token JWT en el almacenamiento local para administrar la sesión del usuario en Angular
- Enviar el token obtenido en el proceso de autenticación en un encabezado de autorización usando la clase `HttpInterceptor`.

## Estructura de la aplicación

Nuestra aplicación de autenticación de usuario angular tendrá tres páginas:
- inicio de sesión
- registro
- perfil de usuario

Hay varias formas estructurar el proyecto en cuanto a la estructura de archivos. Dado que se trata de un proyecto sencillo, utilizaremos, dentro del directorio `app`:
- un directorio `components`, en el que se ubicarán los componentes (en nuestro caso, crearemos un componente por página, pero suelen crearse componentes reutilizables que pueden ser utilizados en varias páginas).
- un directorio `shared`, que contendrá los servicios y clases de uso común en distintos componentes o vistas.

## Desarrollo de la aplicación
### 1. Clonar el Back End que utilizaremos para nuestro proyecto

Antes de comenzar con el desarrollo de nuetra SPA en Angular, levantaremos un Back End local que nos proveerá los servicios necesarios. Utilizaremos una pequeña API REST que provee las siguientes funcionalidades básicas:
- Regsitro
- Inicio de sesión
- Almacenar y obtener datos del usuario

Antes de clonar y ejecutar el Back End, es neceario instalar MongoDB. Te recomiendo seguir [esta guía](https://www.mongodb.com/docs/manual/administration/install-community/) dependiendo de tu sistema operativo.

Ahora sí, para clonar y ejecutar el proyecto, puedes seguir estos pasos desde la terminal:
1. Clonar el repositorio con el comando `git clone https://github.com/SinghDigamber/node-token-based-authentication.git`
2. Entrar en el directorio del proyecto con `cd node-token-based-authentication`
3. Eliminar la carpeta node_modules con el comando `rm -rf node_modules` (esto es necesario porque se han subido las dependnecias de la aplicación al proyecto, lo cual no es una buena práctica... se recomienta siempre agregar la carpeta node_modules en el archivo `.gitignore`)
4. Instalar las dependencias correctas con el comando `npm install`
5. Instalar nodemon y agregarlo como depnedencia de desarrollo al proyecto con el comando `npm install nodemon --save-dev`. Esto nos permitirá ejecutar un servidor que reinicia la aplicación cada vez que ocurre un cambio (en caso de que queramos modificar algo en el código del BE).
7. Agregar el comando nodemon dentro de la propiedad scripts en el archivo `package.json` (ejemplo: `"scripts": {... "nodemon": "nodemon"}`).
8. Ejecutar el servidor con el comando `npm run nodemon`.

A continuación se detalla la interfaz expuesta por la API que acabamos de ejecutar:
|         Métodos             |        URL de la API       |
|:---------------------------:|:--------------------------:|
| GET (Lista de usuarios)     | /api                       |
| POST (Iniciar sesión)       | /api/signin                |
| POST (Registrarse)          | /api/register-user         |
| GET (Perfil de usuario)     | /api/user-profile/:id      |
| PUT (Actualizar Usuario)    | /api/update-user/:id       |
| ELIMINAR (Eliminar Usuario) | /api/delete-user/:id       |

Utilizaremos estos endpoints en nuestro Front End para generar, validar y mostrar la información de los usuarios.

### 2. Inicializar el proyecto utilizando Angular CLI

Ahora que ya tenemos el back End funcionando, podemos comenzar a trabajar en nuestra app. Para inicializar el proyecto Angular, primero debemos instalar el CLI de Angular:
```
npm install -g @angular/cli
```

Una vez instalado el CLI de Angular, podemos inicializar el proyecto con el siguiente comando:
```
ng new angular-meanstack-authentication
```

Nos preguntará si deseamos agregar el enrutador de angular, debemos indicar que sí (aunque también puede hacerse después).

Una vez terminada la generación, nos dirijiros al diretorio del proyecto:
```
cd angular-meanstack-authentication
```

Para confirmar que el proyecto se generó correctamente, podemos ejecutar el siguiente comando y abrir el sitio en el navegador (utilizando la URL `localhost:4200`):
```
ng serve
```

### 3. Agregamos algunas dependencias necesarias

Para nuestro proyecto utilizaremos bootstrap, por lo que primero debemos instalarlo:
```
npm install bootstrap
```

Una vez instalado, debemos agregar la ruta de la hoja de estilos de Bootstrap al [archivo de confguración del proyecto](https://angular.io/guide/workspace-config) `angular.json`:
```
"styles": [
  "node_modules/bootstrap/dist/css/bootstrap.min.css",
  "src/styles.scss"
]
```

### 4. Agregar el HTTP Client de Angular para poder realizar solicitudes HTTP

Como vamos a comunicarnos con el Back End mediante solicitudes HTTP, debemos importar el servicio Angular HttpClient en nuestra app. Para hacerlo, modificaremos el archivo app.module.ts, importando la clase HttpClientModule y agreándola en la lista de imports del módulo:
```
...
import { HttpClientModule } from '@angular/common/http';

@NgModule({
  ...
  imports: [
    ...
    HttpClientModule
  ],
  ...
})
```

### 5. Creamos los componentes para nuestras páginas

Ya cometamos que, debido a que se trata e un proyecto pequeño a modo de ejemplo, crearemos un componente por página. Por el momento, solo los crearemos (no agregaremos el contenido aún).

Ejecuta los siguientes comandos para crear los 3 componentes para las vistas de nuestra app (login, registro y datos del usuario):
```
ng g c components/signin
ng g c components/signup
ng g c components/user-profile
```

Esto generará 3 componentes dentro de la carpeta components, con sus repectivos controladores, templates, hojas de estilos y archivos de test.

### 5. Creamos el servicio de autenticación y la clase de usuario

En nuestra app utilizremos un servico capaz de comunicarse con el Back End para autenticar un usuario, y también una clase User que contendrá los datos del usuario.
Como utilizaremos este servicio y la clase user en distintas partes de la app, crearemos un directorio shared (dentro de app) y allí agregaremos estos archivos.

Crea el archivo `user.ts` dentro del directorio `shared`, con el siguiente código:
```
export class User {
  _id: string;
  name: string;
  email: string;
  password: string;
}
```

Después, genera el servicio de autenticación de usuario:
```
ng g s shared/auth
```

Dentro la clase auth.service.ts, coloca el siguiente código:
```
import { Injectable } from '@angular/core';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import {
  HttpClient,
  HttpHeaders,
  HttpErrorResponse,
} from '@angular/common/http';
import { Router } from '@angular/router';
import { User } from "./user";

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private endpoint: string = 'http://localhost:4000/api';
  private headers = new HttpHeaders().set('Content-Type', 'application/json');
  private currentUser = {};

  public constructor(private http: HttpClient, public router: Router) {}

  // Sign-up
  public signUp(user: User): Observable<any> {
    let api = `${this.endpoint}/register-user`;
    return this.http.post(api, user).pipe(catchError(AuthService.handleError));
  }

  // Sign-in
  public signIn(user: User) {
    return this.http
      .post<any>(`${this.endpoint}/signin`, user)
      .subscribe((res: any) => {
        localStorage.setItem('access_token', res.token);
        this.getUserProfile(res._id).subscribe((res) => {
          this.currentUser = res;
          this.router.navigate(['user-profile/' + res.msg._id]);
        });
      });
  }

  getToken() {
    return localStorage.getItem('access_token');
  }

  get isLoggedIn(): boolean {
    let authToken = localStorage.getItem('access_token');
    return authToken !== null ? true : false;
  }

  public doLogout() {
    let removeToken = localStorage.removeItem('access_token');
    if (removeToken == null) {
      this.router.navigate(['log-in']);
    }
  }

  // User profile
  public getUserProfile(id: any): Observable<any> {
    let api = `${this.endpoint}/user-profile/${id}`;
    return this.http.get(api, { headers: this.headers }).pipe(
      map((res) => {
        return res || {};
      }),
      catchError(AuthService.handleError)
    );
  }

  // Error
  private static handleError(error: HttpErrorResponse) {
    let msg = '';
    if (error.error instanceof ErrorEvent) {
      // client-side error
      msg = error.error.message;
    } else {
      // server-side error
      msg = `Error Code: ${error.status}\nMessage: ${error.message}`;
    }
    return throwError(msg);
  }
}
```
En este código:
- El método signUp() envía el nombre de usuario, el correo electrónico y la contraseña al Back End.
- El método signin() permite al usuario acceder a la aplicación utilizando el JSON Web Token generado por el servidor.
- Obtenemos el token JWT de la respuesta de la API y lo almacenamos en el almacenamiento local; luego, en el método getToken() , accedemos al token a través del método getItem() del almacenamiento local.
- El método isLoggedIn devuelve verdadero si el usuario ha iniciado sesión; de lo contrario, devuelve falso.

### 6. Crear un HttpInterceptor

Ahora agregaremos un HttpInterceptor para agregar el token en el encabezado de nuestras solicitudes al Back End. Lo agregaremos en la carpeta shared:
```
ng g interceptor shared/auth
```

Dentro del archivo creado, agrega el siguiente código:
```
import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor
} from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from "./auth.service";

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

  constructor(private authService: AuthService) { }

  intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    const authToken = this.authService.getToken();
    request = request.clone({
      setHeaders: {
        Authorization: "Bearer " + authToken
      }
    });
    return next.handle(request);
  }
}
```
En el método intercept(){…} llamamos al método getToken() definido anteriormente en el servicio para obtener el token JWT. Luego, utilizando el método request.clone, agregamos el encabezado de Authorization y llamamos al método next.handle() con el contenido del request actualizado.

Para que funcione correctamete, también deberemos agregarlo y configurarlo en el archivo app.module.ts. Agrega este código dentro de la lista de providers del módulo:
```
providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ]
```

### 7. Agregando las rutas para nuestras vistas

Para poder acceder a los distintos componentes utilizando distintas URLs, debemos configurar el router de Angular. Para ello, modifica la constante routes en el archivo app-routing.module.ts. Debería quedar de la sigueinte manera:
```
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { SigninComponent } from "./components/signin/signin.component";
import { SignupComponent } from "./components/signup/signup.component";
import { UserProfileComponent } from "./components/user-profile/user-profile.component";
import { AuthGuard } from "./shared/auth.guard";

const routes: Routes = [
  { path: '', redirectTo: '/log-in', pathMatch: 'full' },
  { path: 'log-in', component: SigninComponent },
  { path: 'sign-up', component: SignupComponent },
  { path: 'user-profile/:id', component: UserProfileComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

### 8. Protegiendo nuestras rutas con CanActivate

Antes de pasar a la implementación de las vistas, vamos a proteger nuestras rutas utilizando un Guard, de modo que, si un usuario no está autenticado, no podŕá acceder a las vistas protegidas (en nuestro caso, la vista de datos del usuario).

Con el siguiente comando agregamos un guard en la carpeta shared:
```
ng g guard shared/auth
```
El CLI te preguntará qué tipo de Guard quieres crear. En este case, crearemos un Guard del tipo CanActivate, por lo que debes seleccionarlo.

Una vez generado, agrega el siguiente código:
```
import { Injectable } from '@angular/core';
import {ActivatedRouteSnapshot, CanActivate, Router, RouterStateSnapshot, UrlTree} from '@angular/router';
import { Observable } from 'rxjs';
import {AuthService} from "./auth.service";

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(
    public authService: AuthService,
    public router: Router
  ) { }
  canActivate(
    next: ActivatedRouteSnapshot,
    state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
    if (!this.authService.isLoggedIn) {
      window.alert("Access not allowed!");
      this.router.navigate(['log-in'])
    }
    return true;
  }
}
```

Como se puede ver, hemos inyectado el servicio `AuthService` en el contructor del Guard para utilizarlo dentro del método `canActivate`. Dentro de este método, utilizamos el getter `isLoggedIn` para saber si el usuario está autenticado. En caso de que lo esté, el método devuelve true (verdadero), caso contrario, redirige hacia la páina de autenticación (`/log-in`).

A continuación, agregaremos el Guard a la ruta `/user-profile/:id` para protegerla. Al hacerlo, Angular llamará el método canActivate definido en el Guard cada vez que queramos acceder a dicha ruta, y bloqueará el acceso en caso de que la respuesta no sea verdadera. Para hacer esto, modifica nuevamente la constante `routes` en el archivo `app-routing.module.ts`. Debería quedar un código similar a este:
```
...
const routes: Routes = [
  { path: '', redirectTo: '/log-in', pathMatch: 'full' },
  { path: 'log-in', component: SigninComponent },
  { path: 'sign-up', component: SignupComponent },
  { path: 'user-profile/:id', component: UserProfileComponent, canActivate: [AuthGuard] }
];
...
```

### 9. Agregado el código para nuestras vistas

Ahora que tenemos los servicios y estucruta listos, vamos a agregar el código para cada una de las páginas de nuestro sitio en los componentes correspondientes.

Para los formularios, utilizaremos los módulos ReactiveFormsModule y FormsModule que nos provee Angular. Si están interesado en aprener más  sobre estos módulos, [este enlace](https://angular.io/guide/reactive-forms) te lleva a la documentación oficial.

El primer paso para utilizar Reactive Forms es agregar estos módulos en el módulo principal de nuestra aplicación (app.module.ts), o en el módulo que queramos utilizarlos. Para hacer esto, hay que importarlos y agregarlos en la lista de imports del módulo:
```
...
import { FormsModule, ReactiveFormsModule } from "@angular/forms";
  
@NgModule({
  ...
  imports: [
    ...
    ReactiveFormsModule,
    FormsModule
  ],
  ...
})
...
```

Ahora, podemos utilizar Reactive Forms en nuestros componentes para crear los formularios necesarios. Comenzaremos por el formulario de registro.

#### Formulario de registro 

Para agregar el formulario de registro en el componente signup.component.ts (dentro de la carpeta components), debemos importar y agregar la clase FormBuilder en el constructor. Esta clase nos provee las funcionalidades necesarias para crear formulario reactivos y utilizarlos en nuestro template.

También utilizaremos el método `signUp` definido en nuestro servicio AuthService (para enviar los datos del formulario al servidor), por lo que igualmente deberemos inyectarlo.

Agrea el siguiente código en el archivo signup.component.ts y observa cómo se crea el controlador del formulario (con el método group) y cómo podemos utilizar su valor para enviar los datos completados por el usuario al Back End (en el método registerUser). 
```
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { AuthService } from '../../shared/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-signup',
  templateUrl: './signup.component.html',
  styleUrls: ['./signup.component.scss'],
})
export class SignupComponent implements OnInit {
  signupForm: FormGroup;
  constructor(
    public fb: FormBuilder,
    public authService: AuthService,
    public router: Router
  ) {
    this.signupForm = this.fb.group({
      name: [''],
      email: [''],
      mobile: [''],
      password: [''],
    });
  }

  ngOnInit() {}

  public registerUser() {
    this.authService.signUp(this.signupForm.value).subscribe((res) => {
      if (res.result) {
        this.signupForm.reset();
        this.router.navigate(['log-in']);
      }
    },
      (err) => {
      console.log(err)
      alert(err.msg || err);
      });
  }
}
```

Una vez creado definida la estructura de los datos del formulario en nuestro controador, es necesario mostrar los campos en el template, junto con el botón para enviar los datos, y enlazarlos con nuestro formulario reactivo. Angular, en el módulo ReactiveForms, provee algunas directivas que nos permitirán enlazar el contenido del formulario y los diferentes campos en el código HTML con el formulario definido en nuestro controlador.

Para esto, editaremos el contenido del archivo signup.component.html con el siguiente código:
```
<div class="auth-wrapper">
  <form
    class="form-signin"
    [formGroup]="signupForm"
    (ngSubmit)="registerUser()"
  >
    <h3 class="h3 mb-3 font-weight-normal text-center">Please sign up</h3>
    <div class="form-group">
      <label>Name</label>
      <input
        type="text"
        class="form-control"
        formControlName="name"
        placeholder="Enter name"
        required
      />
    </div>
    <div class="form-group">
      <label>Email address</label>
      <input
        type="email"
        class="form-control"
        formControlName="email"
        placeholder="Enter email"
        required
      />
    </div>
    <div class="form-group">
      <label>Password</label>
      <input
        type="password"
        class="form-control"
        formControlName="password"
        placeholder="Password"
        required
      />
    </div>
    <button type="submit" class="btn btn-block btn-primary">Sign up</button>
  </form>
</div>
```

En este bloque, dentro de los atributos de las etiquetas HTML, hemos utilizado las siguientes directivas de Angular (Directives):
- `formGroup`, para conectar el formulario con el modelo de datos definido en nuestro controlador (mediante el método `fb.group`)
- `ngSubmit`, para ejecutar una función específica cuando se envía en formulario (en nuestro caso, `registerUser`)
- `formControlName`, para enlazar cada uno de los inputs con la propiedad correspondiente en el modelo definido en el controlador.

En la documentación de [FormsModule](https://angular.io/api/forms/FormsModule) y [ReactiveFormsModule](https://angular.io/guide/reactive-forms) hay información más detallada sobre estas y otras directivas que podemos utilizar en los formularios.

También utilizamos data bindings (`()`, `[]`, `[()]`) para enviar información a los componentes hijos utilizados (en este caso, a la etiqueta form). Podemos utilizar este tipo de bindings para, por ejemplo, pasar valores desde el controlador a los atributos de las  etiquetas HTML, o asignarles el resultado de una expresión. [Este enlace](https://angular.io/guide/binding-syntax) te llevará al sitio oficial de Angular sobre data binding. 

#### Componente de autenticación (login)

Al igual que en el componente de registro (signup), utilizaremos Reactive Forms para crear nuestro formulario de autenticación. Para una breve referencia sobre las directivas y clases utilizadas, vale lo mismo que se dijo sobre el formulario de registro.

Este es el código para el archivo `signin.component.ts`:
```
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { AuthService } from '../../shared/auth.service';
import { Router } from '@angular/router';
@Component({
  selector: 'app-signin',
  templateUrl: './signin.component.html',
  styleUrls: ['./signin.component.scss'],
})
export class SigninComponent implements OnInit {
  signinForm: FormGroup;
  constructor(
    public fb: FormBuilder,
    public authService: AuthService,
    public router: Router
  ) {
    this.signinForm = this.fb.group({
      email: [''],
      password: [''],
    });
  }
  ngOnInit() {}
  loginUser() {
    this.authService.signIn(this.signinForm.value);
  }
}
```

Y para el template (signin.component.html):
```
<div class="auth-wrapper">
  <form class="form-signin" [formGroup]="signinForm" (ngSubmit)="loginUser()">
    <h3 class="h3 mb-3 font-weight-normal text-center">Please sign in</h3>
    <div class="form-group">
      <label>Email</label>
      <input
        type="email"
        class="form-control"
        formControlName="email"
        placeholder="Enter email"
        required
      />
    </div>
    <div class="form-group">
      <label>Password</label>
      <input
        type="password"
        class="form-control"
        formControlName="password"
        placeholder="Password"
      />
    </div>
    <button type="submit" class="btn btn-block btn-primary">Sign in</button>
  </form>
</div>
```

#### Componente de datos del usuario (user-profile)

En el componente de datos del usuario no utilizaremos un formulario, pero sí nuestro servicio AuthService y la clase ActivatedRoute de Angular, por lo que deberemos inyectarlos.

La clase ActivatedRoute nos provee información sobre la ruta que actualmente se encuentra cargada, y la utilizaremos para obtener el ID del usuario logueado, del que queremos mostrar los datos. en la documentación oficial de Angular hay más información sobre [ActivatedRoute](https://angular.io/api/router/ActivatedRoute), sus propiedades y métodos.

También utilizaremos la interpolación de cadenas (string interpolation) para agregar contenido dinámicamente en el HTML nuestro componente. Ésto se logra mediante la utilización de llaves dobles ({{}}) en nuestro código HTML, dentro del cuál podemos utiliar cualquier expresion o variable definida en nuestro componente.

Éste es el código para nuestro componente user-profile.component.ts:
```
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { AuthService } from './../../shared/auth.service';
import {User} from "../../shared/user";
@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
  styleUrls: ['./user-profile.component.scss'],
})
export class UserProfileComponent implements OnInit {
  currentUser?: User;
  constructor(
    public authService: AuthService,
    private actRoute: ActivatedRoute
  ) {
    let id = this.actRoute.snapshot.paramMap.get('id');
    this.authService.getUserProfile(id).subscribe((res) => {
      this.currentUser = res.msg;
    });
  }
  ngOnInit() {}
}
```

Y para el template user-profile.component.html:
```
<div class="container">
  <div class="row">
    <div class="inner-main">
      <h2 class="mb-4">User Profile</h2>
      <p><strong>Name:</strong> {{this.currentUser?.name}}</p>
      <p><strong>Email:</strong> {{this.currentUser?.email}}</p>
    </div>
  </div>
</div>
```
### 10. Agregando el menú de navegación

Finalmente, vamos a agregar un menú de navegación que muestre el contenido correspondiente segń la vista en la que se encuentre el usuario.

Para este paso, modificaremos el contenido del componente AppComponent de nuestra aplicación.

Antes que nada, dirígete al template `app.component.html`, elimina el código inicial que genera el CLI automáticamente y reemplaza su contenido con el sigueinte código HTML:
```
<div
  class="d-flex flex-column flex-md-row align-items-center p-3 px-md-4 mb-3 bg-white border-bottom shadow-sm fixed-top">
  <h5 class="my-0 mr-md-auto font-weight-normal">Angular Auth</h5>
  <nav class="my-2 my-md-0 mr-md-3">
    <a *ngIf="this.authService.isLoggedIn" class="p-2 text-dark">User Profile</a>
    <a *ngIf="!this.authService.isLoggedIn" class="p-2 text-dark" routerLinkActive="active" routerLink="/log-in">Sign
      in</a>
  </nav>
  <a *ngIf="!this.authService.isLoggedIn" class="btn btn-outline-primary" routerLinkActive="active"
     routerLinkActive="active" routerLink="/sign-up">Sign up</a>
  <button (click)="logout()" *ngIf="this.authService.isLoggedIn" type="button" class="btn btn-danger">Logout</button>
</div>

<router-outlet></router-outlet>
```

En este template hemos utilizado la directiva `ngIf` para mostrar u ocultar los elementos de la vista depeniendo del estado de autenticación del usuario.

También hemos utilizado un output binding en el atributo `click` del botón para ejecutar la función `logout` cuando el usuario quiera salir del sitio.

Para finalizar nuestro sitio, vamos a crear la función `logout` en nuestro componente, que llamará al método `doLogout` del servicio `AuthService` (por lo que también deberemos inyectarlo en nuestro controlador):

```
import { Component } from '@angular/core';
import { AuthService } from './shared/auth.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})

export class AppComponent {
  constructor(public authService: AuthService) { }

  logout() {
    this.authService.doLogout();
  }
}
```

## EJECUTAR EL PROYECTO

Ahora que el proyecto está listo, vamos ejecutarlo y probarlo. Debemos ejecutar tanto el Back End como el Front End.

Comenzamos por el Back End. Diríjete al directorio en que clonaste el proyecto que cotiene la API y ejecuta:
```
npm run nodemon
```

Ahora ejecuta el Front End desde el directorio de nuestro proyecto Angular con el siguiente comando:
```
ng serve
```

Finalmente, abre la siguiente URl en el navegador para comenzar a utilizar la app:
```
localhost:4200
```

## Extra: agregando tests

Angular, por defecto, utiliza Karma como herramienta para ejecutar los tests de nuestra app. Si nuestra aplicación no requiere configuraciones especiales, el framework también gestiona la configuración de Karma basándose en el contenido del archivo `angular.json`.

Este enlace lleva a la documentación oficial sobre [testing en Angular](https://angular.io/guide/testing).

### Test de un componente

Al crear un componente con el CLI de Angular, se creará un archivo `*.spec.ts` junto a los archivos del controlador, template y estilos. Este archivo se utiliza para las pruebas unitarias de nuestro componente/servicio.

Este enlace lleva a la documentación oficial sobre [pruebas de componentes en Angular](https://angular.io/guide/testing-components-basics).

El este caso, agregaremos pruebas unitarias al componente `AppComponent`. Como este componente (y su contenido) fue generado automáticamente cuando creamos la aplicación con el CLI, debemos borrar todos los tests existentes antes de proceder (solo dejaremos el primer caso de uso, cuya descripción es `'should create the app'`).

Si intentamos ejecutar este test ahora, fallará. Esto se debe a que nuestro componente tiene algunas dependencias que es necesario inyectar, pero la suite de testing no es capaz de resolver. Podemos comprobarlo con el siguiente comando:
```
ng test --include='**/app.component.spec.ts'
```

Para solucionarlo, debemos agregar las dependencias requeridas por nuestro componente. Para hacerlo debemos modificar la TestBed provista en el test.

Dando un vistazo al archivo `app.component.ts`, notamos que el único servicio que se está inyectado es nuestro `AuthService`. Podemos utilizar varios métodos para resolver esta dependencia, dos de ellas son:
- utilizar un mock del servicio
- inyectar el servicio real (y sus dependencias) y utilizar spies sobre sus métodos

En nuestro caso, tomaremos el primer camino y generaremos un mock de nuestro servicio. Agrega el siguiente código en el archivo de test para crear el mock:

```
class MockAuthService {
  doLogout = () => {}
}
```

Una vez creado el mock, podemos configurar correctamente los providers para nuestro test (dentro de la TestBed ubicada el bloque beforeEach):

```
  await TestBed.configureTestingModule({
    imports: [
      RouterTestingModule
    ],
    declarations: [
      AppComponent
    ],
    providers: [
      { provide: AuthService, useClass: MockAuthService }
    ]
  }).compileComponents();
```

Finalmente, procedemos a agregar algunos tests sobre nuestro componente para verificar algunos comportamientos:
- Que el componente funciona
- Que el título se muestra correctamente
- Que el botón de "Sign in" (login) se muestra correctamente
- Que al ejecutar la función logout, se llama al método doLogout de nuestro AuthService (en este caso, el mock)

Este es el código para los ejemplos (en la documentación de Angular hay otros ejemplos para testear tanto [componentes](https://angular.io/guide/testing-components-basics) como [servicios](https://angular.io/guide/testing-services)):

```
  it('should create the app', () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it('should render title', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h5')?.textContent).toContain('Angular Auth');
  });

  it('should render SignIn', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    const links = compiled.querySelectorAll('a');
    expect(links.item(0).textContent).toContain('Sign in')
  });

  it('' +
    'should logout', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const componentInstance = fixture.componentInstance;
    const logoutSpy = spyOn(componentInstance.authService, 'doLogout');
    fixture.componentInstance.logout();
    expect(logoutSpy).toHaveBeenCalled();
  });
```

Ahora sí, podemos ejecutar nuevamente nuestro test y corroborar que todo funciona según lo esperado:
```
ng test --include='**/app.component.spec.ts'
```
