# angular-jwt-tutorial
Tutorial sobre Angular + JWT (traducción/adaptación de https://www.positronx.io/angular-jwt-user-authentication-tutorial/) 

## Introducción
En esta publicación, vamos a crear un sistema de autenticación de usuario seguro en Angular utilizando JSON Web Token (JWT).

Como back-end para el sistema de autenticación de usuario JWT, clonaremos una API RESTful sencilla desarrollada utilizando node, express y mongoDB (quienes estén interesados pueden visitar [este tutorial](https://www.positronx.io/build-secure-jwt-token-based-authentication-api-with-node/)).

## ¿Qué es JWT (token web JSON)?

JWT se refiere a JSON Web Token. Es un token en forma de string validado y generado por un servidor web. Este token ayuda transferir los datos de forma segura entre el cliente y el servidor de la siguiente manera:
1. La información del usuario (nombre de usuario y contraseña) se envía al servidor mediante una solicitud HTTP POST al servidor web.
2. El servidor web valida la información del usuario, crea un token y lo envía de regreso al cliente.
3. El cliente almacena ese token en el almacenamiento local o en una sesión y, en las próximas llamadas HTTP, lo agrega en el encabezado (headers).
4. El servidor verifica que el token sea válido y devuelve la respuesta al cliente.

## Ejemplo de autenticación de usuario utilizando Angular y JWT

Se pretende realizar un proyecto que cumpla con los siguientes requisitos:
- El usuario debe poder iniciar sesión
- El usuario poder registrarse
- Ocultar/mostrar elementos del menú según el estado de autenticación
- Restringir el acceso del usuario a la página de perfil de usuario cuando el usuario no haya iniciado sesión.
- Almacenar el token JWT en el almacenamiento local para administrar la sesión del usuario en Angular
- Enviar el token obtenido en el proceso de autenticación en un encabezado de autorización usando la clase HttpInterceptor.

## Estructura de la aplicación

Nuestra aplicación de autenticación de usuario angular tendrá tres páginas:
- inicio de sesión
- registro
- perfil de usuario

Hay varias formas estructurar el proyecto en cuanto a los directorios y archivos. Dado que se trata de un proyecto sencillo, utilizaremos, dentro del directorio `app`:
- un directorio `components`, en el que se ubicarán los componentes (en nuestro caso, crearemos un componente por página, pero suelen crearse componentes reutilizables que pueden ser utilizados en varias páginas).
- un directorio `shared`, que contendrá los servicios y clases de uso común en distintos componentes o vistas.

### 1. Clonar el Back End que utilizaremos para nuestro proyecto

Como back end, utilizaremos una pequeña API REST que provee las siguientes funcionalidades básicas:
- Regsitro
- Inicio de sesión
- Almacenar y obtener datos del usuario

Antes de clonar y ejecutar el Back End, es neceario instalar MongoDB. Te recomiendo seguir esta guía dependiendo de tu sistema operativo.

Ahora sí, para clonar y ejecutar el proyecto, puedes seguir estos pasos desde la terminal:
1. Clonar el repositorio con el comando `git clone https://github.com/SinghDigamber/node-token-based-authentication.git`
2. Entrar en el directorio del proyecto con `cd node-token-based-authentication`
3. Eliminar la carpeta node_modules con el comando `rm -rf node_modules` (esto es necesario porque se han subido las dependnecias de la aplicación al proyecto, lo cual no es una buena práctica... se recomienta siempre agregar la carpeta node_modules en el archivo `.gitignore`)
4. Instalar las dependencias correctas con el comando `npm install`
5. Instalar nodemon y agregarlo como depnedencia de desarrollo al proyecto con el comando `npm install nodemon --save-dev`. Esto nos permitirá ejecutar un servidor que reinicia la aplicación cada vez que ocurre un cambio (en caso de que queramos modificar algo en el código del BE).
7. Agregar el comando nodemon dentro de la propiedad scripts en el archivo `package.json` (ejemplo: `"scripts": {... "nodemon": "nodemon"}`).
8. Ejecutar el servidor con el comando `npm run nodemon`.

### 2. Inicializar el proyecto utilizando Angular CLI

Para inicializar el proyecto Angular, primero debemos instalar el CLI de Angular:
```
npm install -g @angular/cli
```

Una vez instalado el CLI de Angular, podemos inicializar el proyecto con el siguiente comando:
```
ng new angular-meanstack-authentication
```

Después, nos dirijiros al diretorio del proyecto:
```
cd angular-meanstack-authentication
```

### 3. Agregamos algunas dependencias necesarias

Para nuestro proyecto utilizaremos bootstrap, por lo que primero debemos instalarlo:

npm install bootstrap

Una vez instalado, debemos agregar la ruta de la hoja de estilos de Bootstrap al archivo de confguración `angular.json`:
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
import { User } from "./entities/user";

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
El CLI te preguntará qué tipo de Guard quieres crear. En este case, crearemos un guard del tipo CanActivate, por lo que debes seleccionarlo.

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
 
Una vez creado el Guard, modifica nuevamente la constante routes en el archivo app-routing.module.ts para proteger la ruta user-profile/:id. Debería quedar un código similar a este:
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
