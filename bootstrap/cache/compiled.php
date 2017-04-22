<?php
namespace Illuminate\Contracts\Container {
use Closure;
interface Container
{
    public function bound($abstract);
    public function alias($abstract, $alias);
    public function tag($abstracts, $tags);
    public function tagged($tag);
    public function bind($abstract, $concrete = null, $shared = false);
    public function bindIf($abstract, $concrete = null, $shared = false);
    public function singleton($abstract, $concrete = null);
    public function extend($abstract, Closure $closure);
    public function instance($abstract, $instance);
    public function when($concrete);
    public function make($abstract, array $parameters = []);
    public function call($callback, array $parameters = [], $defaultMethod = null);
    public function resolved($abstract);
    public function resolving($abstract, Closure $callback = null);
    public function afterResolving($abstract, Closure $callback = null);
}
}

namespace Illuminate\Contracts\Container {
interface ContextualBindingBuilder
{
    public function needs($abstract);
    public function give($implementation);
}
}

namespace Illuminate\Contracts\Foundation {
use Illuminate\Contracts\Container\Container;
interface Application extends Container
{
    public function version();
    public function basePath();
    public function environment();
    public function isDownForMaintenance();
    public function registerConfiguredProviders();
    public function register($provider, $options = [], $force = false);
    public function registerDeferredProvider($provider, $service = null);
    public function boot();
    public function booting($callback);
    public function booted($callback);
    public function getCachedCompilePath();
    public function getCachedServicesPath();
}
}

namespace Illuminate\Contracts\Bus {
interface Dispatcher
{
    public function dispatch($command);
    public function dispatchNow($command, $handler = null);
    public function pipeThrough(array $pipes);
}
}

namespace Illuminate\Contracts\Bus {
interface QueueingDispatcher extends Dispatcher
{
    public function dispatchToQueue($command);
}
}

namespace Illuminate\Contracts\Pipeline {
use Closure;
interface Pipeline
{
    public function send($traveler);
    public function through($stops);
    public function via($method);
    public function then(Closure $destination);
}
}

namespace Illuminate\Contracts\Support {
interface Renderable
{
    public function render();
}
}

namespace Illuminate\Contracts\Logging {
interface Log
{
    public function alert($message, array $context = []);
    public function critical($message, array $context = []);
    public function error($message, array $context = []);
    public function warning($message, array $context = []);
    public function notice($message, array $context = []);
    public function info($message, array $context = []);
    public function debug($message, array $context = []);
    public function log($level, $message, array $context = []);
    public function useFiles($path, $level = 'debug');
    public function useDailyFiles($path, $days = 0, $level = 'debug');
}
}

namespace Illuminate\Contracts\Debug {
use Exception;
interface ExceptionHandler
{
    public function report(Exception $e);
    public function render($request, Exception $e);
    public function renderForConsole($output, Exception $e);
}
}

namespace Illuminate\Contracts\Config {
interface Repository
{
    public function has($key);
    public function get($key, $default = null);
    public function all();
    public function set($key, $value = null);
    public function prepend($key, $value);
    public function push($key, $value);
}
}

namespace Illuminate\Contracts\Events {
interface Dispatcher
{
    public function listen($events, $listener, $priority = 0);
    public function hasListeners($eventName);
    public function push($event, $payload = []);
    public function subscribe($subscriber);
    public function until($event, $payload = []);
    public function flush($event);
    public function fire($event, $payload = [], $halt = false);
    public function firing();
    public function forget($event);
    public function forgetPushed();
}
}

namespace Illuminate\Contracts\Support {
interface Arrayable
{
    public function toArray();
}
}

namespace Illuminate\Contracts\Support {
interface Jsonable
{
    public function toJson($options = 0);
}
}

namespace Illuminate\Contracts\Cookie {
interface Factory
{
    public function make($name, $value, $minutes = 0, $path = null, $domain = null, $secure = false, $httpOnly = true);
    public function forever($name, $value, $path = null, $domain = null, $secure = false, $httpOnly = true);
    public function forget($name, $path = null, $domain = null);
}
}

namespace Illuminate\Contracts\Cookie {
interface QueueingFactory extends Factory
{
    public function queue();
    public function unqueue($name);
    public function getQueuedCookies();
}
}

namespace Illuminate\Contracts\Encryption {
interface Encrypter
{
    public function encrypt($value);
    public function decrypt($payload);
}
}

namespace Illuminate\Contracts\Queue {
interface QueueableEntity
{
    public function getQueueableId();
}
}

namespace Illuminate\Contracts\Routing {
use Closure;
interface Registrar
{
    public function get($uri, $action);
    public function post($uri, $action);
    public function put($uri, $action);
    public function delete($uri, $action);
    public function patch($uri, $action);
    public function options($uri, $action);
    public function match($methods, $uri, $action);
    public function resource($name, $controller, array $options = []);
    public function group(array $attributes, Closure $callback);
    public function substituteBindings($route);
    public function substituteImplicitBindings($route);
}
}

namespace Illuminate\Contracts\Routing {
interface ResponseFactory
{
    public function make($content = '', $status = 200, array $headers = []);
    public function view($view, $data = [], $status = 200, array $headers = []);
    public function json($data = [], $status = 200, array $headers = [], $options = 0);
    public function jsonp($callback, $data = [], $status = 200, array $headers = [], $options = 0);
    public function stream($callback, $status = 200, array $headers = []);
    public function download($file, $name = null, array $headers = [], $disposition = 'attachment');
    public function redirectTo($path, $status = 302, $headers = [], $secure = null);
    public function redirectToRoute($route, $parameters = [], $status = 302, $headers = []);
    public function redirectToAction($action, $parameters = [], $status = 302, $headers = []);
    public function redirectGuest($path, $status = 302, $headers = [], $secure = null);
    public function redirectToIntended($default = '/', $status = 302, $headers = [], $secure = null);
}
}

namespace Illuminate\Contracts\Routing {
interface UrlGenerator
{
    public function current();
    public function to($path, $extra = [], $secure = null);
    public function secure($path, $parameters = []);
    public function asset($path, $secure = null);
    public function route($name, $parameters = [], $absolute = true);
    public function action($action, $parameters = [], $absolute = true);
    public function setRootControllerNamespace($rootNamespace);
}
}

namespace Illuminate\Contracts\Routing {
interface UrlRoutable
{
    public function getRouteKey();
    public function getRouteKeyName();
}
}

namespace Illuminate\Contracts\Validation {
interface ValidatesWhenResolved
{
    public function validate();
}
}

namespace Illuminate\Contracts\View {
interface Factory
{
    public function exists($view);
    public function file($path, $data = [], $mergeData = []);
    public function make($view, $data = [], $mergeData = []);
    public function share($key, $value = null);
    public function composer($views, $callback, $priority = null);
    public function creator($views, $callback);
    public function addNamespace($namespace, $hints);
}
}

namespace Illuminate\Contracts\Support {
interface MessageProvider
{
    public function getMessageBag();
}
}

namespace Illuminate\Contracts\Support {
interface MessageBag
{
    public function keys();
    public function add($key, $message);
    public function merge($messages);
    public function has($key);
    public function first($key = null, $format = null);
    public function get($key, $format = null);
    public function all($format = null);
    public function getFormat();
    public function setFormat($format = ':message');
    public function isEmpty();
    public function count();
    public function toArray();
}
}

namespace Illuminate\Contracts\View {
use Illuminate\Contracts\Support\Renderable;
interface View extends Renderable
{
    public function name();
    public function with($key, $value = null);
}
}

namespace Illuminate\Contracts\Http {
interface Kernel
{
    public function bootstrap();
    public function handle($request);
    public function terminate($request, $response);
    public function getApplication();
}
}

namespace Illuminate\Contracts\Auth {
interface Guard
{
    public function check();
    public function guest();
    public function user();
    public function id();
    public function validate(array $credentials = []);
    public function setUser(Authenticatable $user);
}
}

namespace Illuminate\Contracts\Auth {
interface StatefulGuard extends Guard
{
    public function attempt(array $credentials = [], $remember = false, $login = true);
    public function once(array $credentials = []);
    public function login(Authenticatable $user, $remember = false);
    public function loginUsingId($id, $remember = false);
    public function onceUsingId($id);
    public function viaRemember();
    public function logout();
}
}

namespace Illuminate\Contracts\Auth\Access {
interface Gate
{
    public function has($ability);
    public function define($ability, $callback);
    public function policy($class, $policy);
    public function before(callable $callback);
    public function after(callable $callback);
    public function allows($ability, $arguments = []);
    public function denies($ability, $arguments = []);
    public function check($ability, $arguments = []);
    public function authorize($ability, $arguments = []);
    public function getPolicyFor($class);
    public function forUser($user);
}
}

namespace Illuminate\Contracts\Hashing {
interface Hasher
{
    public function make($value, array $options = []);
    public function check($value, $hashedValue, array $options = []);
    public function needsRehash($hashedValue, array $options = []);
}
}

namespace Illuminate\Auth {
use Closure;
use InvalidArgumentException;
use Illuminate\Contracts\Auth\Factory as FactoryContract;
class AuthManager implements FactoryContract
{
    use CreatesUserProviders;
    protected $app;
    protected $customCreators = [];
    protected $guards = [];
    protected $userResolver;
    public function __construct($app)
    {
        $this->app = $app;
        $this->userResolver = function ($guard = null) {
            return $this->guard($guard)->user();
        };
    }
    public function guard($name = null)
    {
        $name = $name ?: $this->getDefaultDriver();
        return isset($this->guards[$name]) ? $this->guards[$name] : ($this->guards[$name] = $this->resolve($name));
    }
    protected function resolve($name)
    {
        $config = $this->getConfig($name);
        if (is_null($config)) {
            throw new InvalidArgumentException("Auth guard [{$name}] is not defined.");
        }
        if (isset($this->customCreators[$config['driver']])) {
            return $this->callCustomCreator($name, $config);
        }
        $driverMethod = 'create' . ucfirst($config['driver']) . 'Driver';
        if (method_exists($this, $driverMethod)) {
            return $this->{$driverMethod}($name, $config);
        }
        throw new InvalidArgumentException("Auth guard driver [{$name}] is not defined.");
    }
    protected function callCustomCreator($name, array $config)
    {
        return $this->customCreators[$config['driver']]($this->app, $name, $config);
    }
    public function createSessionDriver($name, $config)
    {
        $provider = $this->createUserProvider($config['provider']);
        $guard = new SessionGuard($name, $provider, $this->app['session.store']);
        if (method_exists($guard, 'setCookieJar')) {
            $guard->setCookieJar($this->app['cookie']);
        }
        if (method_exists($guard, 'setDispatcher')) {
            $guard->setDispatcher($this->app['events']);
        }
        if (method_exists($guard, 'setRequest')) {
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
        }
        return $guard;
    }
    public function createTokenDriver($name, $config)
    {
        $guard = new TokenGuard($this->createUserProvider($config['provider']), $this->app['request']);
        $this->app->refresh('request', $guard, 'setRequest');
        return $guard;
    }
    protected function getConfig($name)
    {
        return $this->app['config']["auth.guards.{$name}"];
    }
    public function getDefaultDriver()
    {
        return $this->app['config']['auth.defaults.guard'];
    }
    public function shouldUse($name)
    {
        $name = $name ?: $this->getDefaultDriver();
        $this->setDefaultDriver($name);
        $this->userResolver = function ($name = null) {
            return $this->guard($name)->user();
        };
    }
    public function setDefaultDriver($name)
    {
        $this->app['config']['auth.defaults.guard'] = $name;
    }
    public function viaRequest($driver, callable $callback)
    {
        return $this->extend($driver, function () use($callback) {
            $guard = new RequestGuard($callback, $this->app['request']);
            $this->app->refresh('request', $guard, 'setRequest');
            return $guard;
        });
    }
    public function userResolver()
    {
        return $this->userResolver;
    }
    public function resolveUsersUsing(Closure $userResolver)
    {
        $this->userResolver = $userResolver;
        return $this;
    }
    public function extend($driver, Closure $callback)
    {
        $this->customCreators[$driver] = $callback;
        return $this;
    }
    public function provider($name, Closure $callback)
    {
        $this->customProviderCreators[$name] = $callback;
        return $this;
    }
    public function __call($method, $parameters)
    {
        return $this->guard()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Auth {
use RuntimeException;
use Illuminate\Support\Str;
use Illuminate\Http\Response;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Symfony\Component\HttpFoundation\Request;
use Illuminate\Contracts\Auth\SupportsBasicAuth;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
class SessionGuard implements StatefulGuard, SupportsBasicAuth
{
    use GuardHelpers;
    protected $name;
    protected $lastAttempted;
    protected $viaRemember = false;
    protected $session;
    protected $cookie;
    protected $request;
    protected $events;
    protected $loggedOut = false;
    protected $tokenRetrievalAttempted = false;
    public function __construct($name, UserProvider $provider, SessionInterface $session, Request $request = null)
    {
        $this->name = $name;
        $this->session = $session;
        $this->request = $request;
        $this->provider = $provider;
    }
    public function user()
    {
        if ($this->loggedOut) {
            return;
        }
        if (!is_null($this->user)) {
            return $this->user;
        }
        $id = $this->session->get($this->getName());
        $user = null;
        if (!is_null($id)) {
            if ($user = $this->provider->retrieveById($id)) {
                $this->fireAuthenticatedEvent($user);
            }
        }
        $recaller = $this->getRecaller();
        if (is_null($user) && !is_null($recaller)) {
            $user = $this->getUserByRecaller($recaller);
            if ($user) {
                $this->updateSession($user->getAuthIdentifier());
                $this->fireLoginEvent($user, true);
            }
        }
        return $this->user = $user;
    }
    public function id()
    {
        if ($this->loggedOut) {
            return;
        }
        $id = $this->session->get($this->getName());
        if (is_null($id) && $this->user()) {
            $id = $this->user()->getAuthIdentifier();
        }
        return $id;
    }
    protected function getUserByRecaller($recaller)
    {
        if ($this->validRecaller($recaller) && !$this->tokenRetrievalAttempted) {
            $this->tokenRetrievalAttempted = true;
            list($id, $token) = explode('|', $recaller, 2);
            $this->viaRemember = !is_null($user = $this->provider->retrieveByToken($id, $token));
            return $user;
        }
    }
    protected function getRecaller()
    {
        return $this->request->cookies->get($this->getRecallerName());
    }
    protected function getRecallerId()
    {
        if ($this->validRecaller($recaller = $this->getRecaller())) {
            return head(explode('|', $recaller));
        }
    }
    protected function validRecaller($recaller)
    {
        if (!is_string($recaller) || !Str::contains($recaller, '|')) {
            return false;
        }
        $segments = explode('|', $recaller);
        return count($segments) == 2 && trim($segments[0]) !== '' && trim($segments[1]) !== '';
    }
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);
            return true;
        }
        return false;
    }
    public function validate(array $credentials = [])
    {
        return $this->attempt($credentials, false, false);
    }
    public function basic($field = 'email', $extraConditions = [])
    {
        if ($this->check()) {
            return;
        }
        if ($this->attemptBasic($this->getRequest(), $field, $extraConditions)) {
            return;
        }
        return $this->getBasicResponse();
    }
    public function onceBasic($field = 'email', $extraConditions = [])
    {
        $credentials = $this->getBasicCredentials($this->getRequest(), $field);
        if (!$this->once(array_merge($credentials, $extraConditions))) {
            return $this->getBasicResponse();
        }
    }
    protected function attemptBasic(Request $request, $field, $extraConditions = [])
    {
        if (!$request->getUser()) {
            return false;
        }
        $credentials = $this->getBasicCredentials($request, $field);
        return $this->attempt(array_merge($credentials, $extraConditions));
    }
    protected function getBasicCredentials(Request $request, $field)
    {
        return [$field => $request->getUser(), 'password' => $request->getPassword()];
    }
    protected function getBasicResponse()
    {
        $headers = ['WWW-Authenticate' => 'Basic'];
        return new Response('Invalid credentials.', 401, $headers);
    }
    public function attempt(array $credentials = [], $remember = false, $login = true)
    {
        $this->fireAttemptEvent($credentials, $remember, $login);
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            if ($login) {
                $this->login($user, $remember);
            }
            return true;
        }
        if ($login) {
            $this->fireFailedEvent($user, $credentials);
        }
        return false;
    }
    protected function hasValidCredentials($user, $credentials)
    {
        return !is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }
    protected function fireAttemptEvent(array $credentials, $remember, $login)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Attempting($credentials, $remember, $login));
        }
    }
    protected function fireFailedEvent($user, array $credentials)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Failed($user, $credentials));
        }
    }
    public function attempting($callback)
    {
        if (isset($this->events)) {
            $this->events->listen(Events\Attempting::class, $callback);
        }
    }
    public function login(AuthenticatableContract $user, $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());
        if ($remember) {
            $this->createRememberTokenIfDoesntExist($user);
            $this->queueRecallerCookie($user);
        }
        $this->fireLoginEvent($user, $remember);
        $this->setUser($user);
    }
    protected function fireLoginEvent($user, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Login($user, $remember));
        }
    }
    protected function fireAuthenticatedEvent($user)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Authenticated($user));
        }
    }
    protected function updateSession($id)
    {
        $this->session->set($this->getName(), $id);
        $this->session->migrate(true);
    }
    public function loginUsingId($id, $remember = false)
    {
        $user = $this->provider->retrieveById($id);
        if (!is_null($user)) {
            $this->login($user, $remember);
            return $user;
        }
        return false;
    }
    public function onceUsingId($id)
    {
        $user = $this->provider->retrieveById($id);
        if (!is_null($user)) {
            $this->setUser($user);
            return $user;
        }
        return false;
    }
    protected function queueRecallerCookie(AuthenticatableContract $user)
    {
        $value = $user->getAuthIdentifier() . '|' . $user->getRememberToken();
        $this->getCookieJar()->queue($this->createRecaller($value));
    }
    protected function createRecaller($value)
    {
        return $this->getCookieJar()->forever($this->getRecallerName(), $value);
    }
    public function logout()
    {
        $user = $this->user();
        $this->clearUserDataFromStorage();
        if (!is_null($this->user)) {
            $this->refreshRememberToken($user);
        }
        if (isset($this->events)) {
            $this->events->fire(new Events\Logout($user));
        }
        $this->user = null;
        $this->loggedOut = true;
    }
    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());
        if (!is_null($this->getRecaller())) {
            $recaller = $this->getRecallerName();
            $this->getCookieJar()->queue($this->getCookieJar()->forget($recaller));
        }
    }
    protected function refreshRememberToken(AuthenticatableContract $user)
    {
        $user->setRememberToken($token = Str::random(60));
        $this->provider->updateRememberToken($user, $token);
    }
    protected function createRememberTokenIfDoesntExist(AuthenticatableContract $user)
    {
        if (empty($user->getRememberToken())) {
            $this->refreshRememberToken($user);
        }
    }
    public function getCookieJar()
    {
        if (!isset($this->cookie)) {
            throw new RuntimeException('Cookie jar has not been set.');
        }
        return $this->cookie;
    }
    public function setCookieJar(CookieJar $cookie)
    {
        $this->cookie = $cookie;
    }
    public function getDispatcher()
    {
        return $this->events;
    }
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }
    public function getSession()
    {
        return $this->session;
    }
    public function getProvider()
    {
        return $this->provider;
    }
    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;
    }
    public function getUser()
    {
        return $this->user;
    }
    public function setUser(AuthenticatableContract $user)
    {
        $this->user = $user;
        $this->loggedOut = false;
        $this->fireAuthenticatedEvent($user);
        return $this;
    }
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }
    public function setRequest(Request $request)
    {
        $this->request = $request;
        return $this;
    }
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }
    public function getName()
    {
        return 'login_' . $this->name . '_' . sha1(static::class);
    }
    public function getRecallerName()
    {
        return 'remember_' . $this->name . '_' . sha1(static::class);
    }
    public function viaRemember()
    {
        return $this->viaRemember;
    }
}
}

namespace Illuminate\Auth\Access {
use Illuminate\Support\Str;
use InvalidArgumentException;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
class Gate implements GateContract
{
    use HandlesAuthorization;
    protected $container;
    protected $userResolver;
    protected $abilities = [];
    protected $policies = [];
    protected $beforeCallbacks = [];
    protected $afterCallbacks = [];
    public function __construct(Container $container, callable $userResolver, array $abilities = [], array $policies = [], array $beforeCallbacks = [], array $afterCallbacks = [])
    {
        $this->policies = $policies;
        $this->container = $container;
        $this->abilities = $abilities;
        $this->userResolver = $userResolver;
        $this->afterCallbacks = $afterCallbacks;
        $this->beforeCallbacks = $beforeCallbacks;
    }
    public function has($ability)
    {
        return isset($this->abilities[$ability]);
    }
    public function define($ability, $callback)
    {
        if (is_callable($callback)) {
            $this->abilities[$ability] = $callback;
        } elseif (is_string($callback) && Str::contains($callback, '@')) {
            $this->abilities[$ability] = $this->buildAbilityCallback($callback);
        } else {
            throw new InvalidArgumentException("Callback must be a callable or a 'Class@method' string.");
        }
        return $this;
    }
    protected function buildAbilityCallback($callback)
    {
        return function () use($callback) {
            list($class, $method) = explode('@', $callback);
            return $this->resolvePolicy($class)->{$method}(...func_get_args());
        };
    }
    public function policy($class, $policy)
    {
        $this->policies[$class] = $policy;
        return $this;
    }
    public function before(callable $callback)
    {
        $this->beforeCallbacks[] = $callback;
        return $this;
    }
    public function after(callable $callback)
    {
        $this->afterCallbacks[] = $callback;
        return $this;
    }
    public function allows($ability, $arguments = [])
    {
        return $this->check($ability, $arguments);
    }
    public function denies($ability, $arguments = [])
    {
        return !$this->allows($ability, $arguments);
    }
    public function check($ability, $arguments = [])
    {
        try {
            $result = $this->raw($ability, $arguments);
        } catch (AuthorizationException $e) {
            return false;
        }
        return (bool) $result;
    }
    public function authorize($ability, $arguments = [])
    {
        $result = $this->raw($ability, $arguments);
        if ($result instanceof Response) {
            return $result;
        }
        return $result ? $this->allow() : $this->deny();
    }
    protected function raw($ability, $arguments = [])
    {
        if (!($user = $this->resolveUser())) {
            return false;
        }
        $arguments = is_array($arguments) ? $arguments : [$arguments];
        if (is_null($result = $this->callBeforeCallbacks($user, $ability, $arguments))) {
            $result = $this->callAuthCallback($user, $ability, $arguments);
        }
        $this->callAfterCallbacks($user, $ability, $arguments, $result);
        return $result;
    }
    protected function callAuthCallback($user, $ability, array $arguments)
    {
        $callback = $this->resolveAuthCallback($user, $ability, $arguments);
        return $callback($user, ...$arguments);
    }
    protected function callBeforeCallbacks($user, $ability, array $arguments)
    {
        $arguments = array_merge([$user, $ability], [$arguments]);
        foreach ($this->beforeCallbacks as $before) {
            if (!is_null($result = $before(...$arguments))) {
                return $result;
            }
        }
    }
    protected function callAfterCallbacks($user, $ability, array $arguments, $result)
    {
        $arguments = array_merge([$user, $ability, $result], [$arguments]);
        foreach ($this->afterCallbacks as $after) {
            $after(...$arguments);
        }
    }
    protected function resolveAuthCallback($user, $ability, array $arguments)
    {
        if ($this->firstArgumentCorrespondsToPolicy($arguments)) {
            return $this->resolvePolicyCallback($user, $ability, $arguments);
        } elseif (isset($this->abilities[$ability])) {
            return $this->abilities[$ability];
        } else {
            return function () {
                return false;
            };
        }
    }
    protected function firstArgumentCorrespondsToPolicy(array $arguments)
    {
        if (!isset($arguments[0])) {
            return false;
        }
        if (is_object($arguments[0])) {
            return isset($this->policies[get_class($arguments[0])]);
        }
        return is_string($arguments[0]) && isset($this->policies[$arguments[0]]);
    }
    protected function resolvePolicyCallback($user, $ability, array $arguments)
    {
        return function () use($user, $ability, $arguments) {
            $instance = $this->getPolicyFor($arguments[0]);
            if (method_exists($instance, 'before')) {
                if (!is_null($result = $instance->before($user, $ability, ...$arguments))) {
                    return $result;
                }
            }
            if (strpos($ability, '-') !== false) {
                $ability = Str::camel($ability);
            }
            if (isset($arguments[0]) && is_string($arguments[0])) {
                array_shift($arguments);
            }
            if (!is_callable([$instance, $ability])) {
                return false;
            }
            return $instance->{$ability}($user, ...$arguments);
        };
    }
    public function getPolicyFor($class)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }
        if (!isset($this->policies[$class])) {
            throw new InvalidArgumentException("Policy not defined for [{$class}].");
        }
        return $this->resolvePolicy($this->policies[$class]);
    }
    public function resolvePolicy($class)
    {
        return $this->container->make($class);
    }
    public function forUser($user)
    {
        $callback = function () use($user) {
            return $user;
        };
        return new static($this->container, $callback, $this->abilities, $this->policies, $this->beforeCallbacks, $this->afterCallbacks);
    }
    protected function resolveUser()
    {
        return call_user_func($this->userResolver);
    }
}
}

namespace Illuminate\Contracts\Auth {
interface UserProvider
{
    public function retrieveById($identifier);
    public function retrieveByToken($identifier, $token);
    public function updateRememberToken(Authenticatable $user, $token);
    public function retrieveByCredentials(array $credentials);
    public function validateCredentials(Authenticatable $user, array $credentials);
}
}

namespace Illuminate\Auth {
use Illuminate\Support\Str;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;
class EloquentUserProvider implements UserProvider
{
    protected $hasher;
    protected $model;
    public function __construct(HasherContract $hasher, $model)
    {
        $this->model = $model;
        $this->hasher = $hasher;
    }
    public function retrieveById($identifier)
    {
        return $this->createModel()->newQuery()->find($identifier);
    }
    public function retrieveByToken($identifier, $token)
    {
        $model = $this->createModel();
        return $model->newQuery()->where($model->getAuthIdentifierName(), $identifier)->where($model->getRememberTokenName(), $token)->first();
    }
    public function updateRememberToken(UserContract $user, $token)
    {
        $user->setRememberToken($token);
        $user->save();
    }
    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials)) {
            return;
        }
        $query = $this->createModel()->newQuery();
        foreach ($credentials as $key => $value) {
            if (!Str::contains($key, 'password')) {
                $query->where($key, $value);
            }
        }
        return $query->first();
    }
    public function validateCredentials(UserContract $user, array $credentials)
    {
        $plain = $credentials['password'];
        return $this->hasher->check($plain, $user->getAuthPassword());
    }
    public function createModel()
    {
        $class = '\\' . ltrim($this->model, '\\');
        return new $class();
    }
    public function getHasher()
    {
        return $this->hasher;
    }
    public function setHasher(HasherContract $hasher)
    {
        $this->hasher = $hasher;
        return $this;
    }
    public function getModel()
    {
        return $this->model;
    }
    public function setModel($model)
    {
        $this->model = $model;
        return $this;
    }
}
}

namespace Illuminate\Container {
use Closure;
use ArrayAccess;
use LogicException;
use ReflectionClass;
use ReflectionMethod;
use ReflectionFunction;
use ReflectionParameter;
use InvalidArgumentException;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container as ContainerContract;
class Container implements ArrayAccess, ContainerContract
{
    protected static $instance;
    protected $resolved = [];
    protected $bindings = [];
    protected $instances = [];
    protected $aliases = [];
    protected $extenders = [];
    protected $tags = [];
    protected $buildStack = [];
    public $contextual = [];
    protected $reboundCallbacks = [];
    protected $globalResolvingCallbacks = [];
    protected $globalAfterResolvingCallbacks = [];
    protected $resolvingCallbacks = [];
    protected $afterResolvingCallbacks = [];
    public function when($concrete)
    {
        $concrete = $this->normalize($concrete);
        return new ContextualBindingBuilder($this, $concrete);
    }
    public function bound($abstract)
    {
        $abstract = $this->normalize($abstract);
        return isset($this->bindings[$abstract]) || isset($this->instances[$abstract]) || $this->isAlias($abstract);
    }
    public function resolved($abstract)
    {
        $abstract = $this->normalize($abstract);
        if ($this->isAlias($abstract)) {
            $abstract = $this->getAlias($abstract);
        }
        return isset($this->resolved[$abstract]) || isset($this->instances[$abstract]);
    }
    public function isAlias($name)
    {
        return isset($this->aliases[$this->normalize($name)]);
    }
    public function bind($abstract, $concrete = null, $shared = false)
    {
        $abstract = $this->normalize($abstract);
        $concrete = $this->normalize($concrete);
        if (is_array($abstract)) {
            list($abstract, $alias) = $this->extractAlias($abstract);
            $this->alias($abstract, $alias);
        }
        $this->dropStaleInstances($abstract);
        if (is_null($concrete)) {
            $concrete = $abstract;
        }
        if (!$concrete instanceof Closure) {
            $concrete = $this->getClosure($abstract, $concrete);
        }
        $this->bindings[$abstract] = compact('concrete', 'shared');
        if ($this->resolved($abstract)) {
            $this->rebound($abstract);
        }
    }
    protected function getClosure($abstract, $concrete)
    {
        return function ($container, $parameters = []) use($abstract, $concrete) {
            $method = $abstract == $concrete ? 'build' : 'make';
            return $container->{$method}($concrete, $parameters);
        };
    }
    public function addContextualBinding($concrete, $abstract, $implementation)
    {
        $this->contextual[$this->normalize($concrete)][$this->normalize($abstract)] = $this->normalize($implementation);
    }
    public function bindIf($abstract, $concrete = null, $shared = false)
    {
        if (!$this->bound($abstract)) {
            $this->bind($abstract, $concrete, $shared);
        }
    }
    public function singleton($abstract, $concrete = null)
    {
        $this->bind($abstract, $concrete, true);
    }
    public function share(Closure $closure)
    {
        return function ($container) use($closure) {
            static $object;
            if (is_null($object)) {
                $object = $closure($container);
            }
            return $object;
        };
    }
    public function extend($abstract, Closure $closure)
    {
        $abstract = $this->normalize($abstract);
        if (isset($this->instances[$abstract])) {
            $this->instances[$abstract] = $closure($this->instances[$abstract], $this);
            $this->rebound($abstract);
        } else {
            $this->extenders[$abstract][] = $closure;
        }
    }
    public function instance($abstract, $instance)
    {
        $abstract = $this->normalize($abstract);
        if (is_array($abstract)) {
            list($abstract, $alias) = $this->extractAlias($abstract);
            $this->alias($abstract, $alias);
        }
        unset($this->aliases[$abstract]);
        $bound = $this->bound($abstract);
        $this->instances[$abstract] = $instance;
        if ($bound) {
            $this->rebound($abstract);
        }
    }
    public function tag($abstracts, $tags)
    {
        $tags = is_array($tags) ? $tags : array_slice(func_get_args(), 1);
        foreach ($tags as $tag) {
            if (!isset($this->tags[$tag])) {
                $this->tags[$tag] = [];
            }
            foreach ((array) $abstracts as $abstract) {
                $this->tags[$tag][] = $this->normalize($abstract);
            }
        }
    }
    public function tagged($tag)
    {
        $results = [];
        if (isset($this->tags[$tag])) {
            foreach ($this->tags[$tag] as $abstract) {
                $results[] = $this->make($abstract);
            }
        }
        return $results;
    }
    public function alias($abstract, $alias)
    {
        $this->aliases[$alias] = $this->normalize($abstract);
    }
    protected function extractAlias(array $definition)
    {
        return [key($definition), current($definition)];
    }
    public function rebinding($abstract, Closure $callback)
    {
        $this->reboundCallbacks[$this->normalize($abstract)][] = $callback;
        if ($this->bound($abstract)) {
            return $this->make($abstract);
        }
    }
    public function refresh($abstract, $target, $method)
    {
        return $this->rebinding($this->normalize($abstract), function ($app, $instance) use($target, $method) {
            $target->{$method}($instance);
        });
    }
    protected function rebound($abstract)
    {
        $instance = $this->make($abstract);
        foreach ($this->getReboundCallbacks($abstract) as $callback) {
            call_user_func($callback, $this, $instance);
        }
    }
    protected function getReboundCallbacks($abstract)
    {
        if (isset($this->reboundCallbacks[$abstract])) {
            return $this->reboundCallbacks[$abstract];
        }
        return [];
    }
    public function wrap(Closure $callback, array $parameters = [])
    {
        return function () use($callback, $parameters) {
            return $this->call($callback, $parameters);
        };
    }
    public function call($callback, array $parameters = [], $defaultMethod = null)
    {
        if ($this->isCallableWithAtSign($callback) || $defaultMethod) {
            return $this->callClass($callback, $parameters, $defaultMethod);
        }
        $dependencies = $this->getMethodDependencies($callback, $parameters);
        return call_user_func_array($callback, $dependencies);
    }
    protected function isCallableWithAtSign($callback)
    {
        return is_string($callback) && strpos($callback, '@') !== false;
    }
    protected function getMethodDependencies($callback, array $parameters = [])
    {
        $dependencies = [];
        foreach ($this->getCallReflector($callback)->getParameters() as $parameter) {
            $this->addDependencyForCallParameter($parameter, $parameters, $dependencies);
        }
        return array_merge($dependencies, $parameters);
    }
    protected function getCallReflector($callback)
    {
        if (is_string($callback) && strpos($callback, '::') !== false) {
            $callback = explode('::', $callback);
        }
        if (is_array($callback)) {
            return new ReflectionMethod($callback[0], $callback[1]);
        }
        return new ReflectionFunction($callback);
    }
    protected function addDependencyForCallParameter(ReflectionParameter $parameter, array &$parameters, &$dependencies)
    {
        if (array_key_exists($parameter->name, $parameters)) {
            $dependencies[] = $parameters[$parameter->name];
            unset($parameters[$parameter->name]);
        } elseif ($parameter->getClass()) {
            $dependencies[] = $this->make($parameter->getClass()->name);
        } elseif ($parameter->isDefaultValueAvailable()) {
            $dependencies[] = $parameter->getDefaultValue();
        }
    }
    protected function callClass($target, array $parameters = [], $defaultMethod = null)
    {
        $segments = explode('@', $target);
        $method = count($segments) == 2 ? $segments[1] : $defaultMethod;
        if (is_null($method)) {
            throw new InvalidArgumentException('Method not provided.');
        }
        return $this->call([$this->make($segments[0]), $method], $parameters);
    }
    public function factory($abstract, array $defaults = [])
    {
        return function (array $params = []) use($abstract, $defaults) {
            return $this->make($abstract, $params + $defaults);
        };
    }
    public function make($abstract, array $parameters = [])
    {
        $abstract = $this->getAlias($this->normalize($abstract));
        if (isset($this->instances[$abstract])) {
            return $this->instances[$abstract];
        }
        $concrete = $this->getConcrete($abstract);
        if ($this->isBuildable($concrete, $abstract)) {
            $object = $this->build($concrete, $parameters);
        } else {
            $object = $this->make($concrete, $parameters);
        }
        foreach ($this->getExtenders($abstract) as $extender) {
            $object = $extender($object, $this);
        }
        if ($this->isShared($abstract)) {
            $this->instances[$abstract] = $object;
        }
        $this->fireResolvingCallbacks($abstract, $object);
        $this->resolved[$abstract] = true;
        return $object;
    }
    protected function getConcrete($abstract)
    {
        if (!is_null($concrete = $this->getContextualConcrete($abstract))) {
            return $concrete;
        }
        if (!isset($this->bindings[$abstract])) {
            return $abstract;
        }
        return $this->bindings[$abstract]['concrete'];
    }
    protected function getContextualConcrete($abstract)
    {
        if (isset($this->contextual[end($this->buildStack)][$abstract])) {
            return $this->contextual[end($this->buildStack)][$abstract];
        }
    }
    protected function normalize($service)
    {
        return is_string($service) ? ltrim($service, '\\') : $service;
    }
    protected function getExtenders($abstract)
    {
        if (isset($this->extenders[$abstract])) {
            return $this->extenders[$abstract];
        }
        return [];
    }
    public function build($concrete, array $parameters = [])
    {
        if ($concrete instanceof Closure) {
            return $concrete($this, $parameters);
        }
        $reflector = new ReflectionClass($concrete);
        if (!$reflector->isInstantiable()) {
            if (!empty($this->buildStack)) {
                $previous = implode(', ', $this->buildStack);
                $message = "Target [{$concrete}] is not instantiable while building [{$previous}].";
            } else {
                $message = "Target [{$concrete}] is not instantiable.";
            }
            throw new BindingResolutionException($message);
        }
        $this->buildStack[] = $concrete;
        $constructor = $reflector->getConstructor();
        if (is_null($constructor)) {
            array_pop($this->buildStack);
            return new $concrete();
        }
        $dependencies = $constructor->getParameters();
        $parameters = $this->keyParametersByArgument($dependencies, $parameters);
        $instances = $this->getDependencies($dependencies, $parameters);
        array_pop($this->buildStack);
        return $reflector->newInstanceArgs($instances);
    }
    protected function getDependencies(array $parameters, array $primitives = [])
    {
        $dependencies = [];
        foreach ($parameters as $parameter) {
            $dependency = $parameter->getClass();
            if (array_key_exists($parameter->name, $primitives)) {
                $dependencies[] = $primitives[$parameter->name];
            } elseif (is_null($dependency)) {
                $dependencies[] = $this->resolveNonClass($parameter);
            } else {
                $dependencies[] = $this->resolveClass($parameter);
            }
        }
        return $dependencies;
    }
    protected function resolveNonClass(ReflectionParameter $parameter)
    {
        if (!is_null($concrete = $this->getContextualConcrete('$' . $parameter->name))) {
            if ($concrete instanceof Closure) {
                return call_user_func($concrete, $this);
            } else {
                return $concrete;
            }
        }
        if ($parameter->isDefaultValueAvailable()) {
            return $parameter->getDefaultValue();
        }
        $message = "Unresolvable dependency resolving [{$parameter}] in class {$parameter->getDeclaringClass()->getName()}";
        throw new BindingResolutionException($message);
    }
    protected function resolveClass(ReflectionParameter $parameter)
    {
        try {
            return $this->make($parameter->getClass()->name);
        } catch (BindingResolutionException $e) {
            if ($parameter->isOptional()) {
                return $parameter->getDefaultValue();
            }
            throw $e;
        }
    }
    protected function keyParametersByArgument(array $dependencies, array $parameters)
    {
        foreach ($parameters as $key => $value) {
            if (is_numeric($key)) {
                unset($parameters[$key]);
                $parameters[$dependencies[$key]->name] = $value;
            }
        }
        return $parameters;
    }
    public function resolving($abstract, Closure $callback = null)
    {
        if (is_null($callback) && $abstract instanceof Closure) {
            $this->resolvingCallback($abstract);
        } else {
            $this->resolvingCallbacks[$this->normalize($abstract)][] = $callback;
        }
    }
    public function afterResolving($abstract, Closure $callback = null)
    {
        if ($abstract instanceof Closure && is_null($callback)) {
            $this->afterResolvingCallback($abstract);
        } else {
            $this->afterResolvingCallbacks[$this->normalize($abstract)][] = $callback;
        }
    }
    protected function resolvingCallback(Closure $callback)
    {
        $abstract = $this->getFunctionHint($callback);
        if ($abstract) {
            $this->resolvingCallbacks[$abstract][] = $callback;
        } else {
            $this->globalResolvingCallbacks[] = $callback;
        }
    }
    protected function afterResolvingCallback(Closure $callback)
    {
        $abstract = $this->getFunctionHint($callback);
        if ($abstract) {
            $this->afterResolvingCallbacks[$abstract][] = $callback;
        } else {
            $this->globalAfterResolvingCallbacks[] = $callback;
        }
    }
    protected function getFunctionHint(Closure $callback)
    {
        $function = new ReflectionFunction($callback);
        if ($function->getNumberOfParameters() == 0) {
            return;
        }
        $expected = $function->getParameters()[0];
        if (!$expected->getClass()) {
            return;
        }
        return $expected->getClass()->name;
    }
    protected function fireResolvingCallbacks($abstract, $object)
    {
        $this->fireCallbackArray($object, $this->globalResolvingCallbacks);
        $this->fireCallbackArray($object, $this->getCallbacksForType($abstract, $object, $this->resolvingCallbacks));
        $this->fireCallbackArray($object, $this->globalAfterResolvingCallbacks);
        $this->fireCallbackArray($object, $this->getCallbacksForType($abstract, $object, $this->afterResolvingCallbacks));
    }
    protected function getCallbacksForType($abstract, $object, array $callbacksPerType)
    {
        $results = [];
        foreach ($callbacksPerType as $type => $callbacks) {
            if ($type === $abstract || $object instanceof $type) {
                $results = array_merge($results, $callbacks);
            }
        }
        return $results;
    }
    protected function fireCallbackArray($object, array $callbacks)
    {
        foreach ($callbacks as $callback) {
            $callback($object, $this);
        }
    }
    public function isShared($abstract)
    {
        $abstract = $this->normalize($abstract);
        if (isset($this->instances[$abstract])) {
            return true;
        }
        if (!isset($this->bindings[$abstract]['shared'])) {
            return false;
        }
        return $this->bindings[$abstract]['shared'] === true;
    }
    protected function isBuildable($concrete, $abstract)
    {
        return $concrete === $abstract || $concrete instanceof Closure;
    }
    public function getAlias($abstract)
    {
        if (!isset($this->aliases[$abstract])) {
            return $abstract;
        }
        if ($this->aliases[$abstract] === $abstract) {
            throw new LogicException("[{$abstract}] is aliased to itself.");
        }
        return $this->getAlias($this->aliases[$abstract]);
    }
    public function getBindings()
    {
        return $this->bindings;
    }
    protected function dropStaleInstances($abstract)
    {
        unset($this->instances[$abstract], $this->aliases[$abstract]);
    }
    public function forgetInstance($abstract)
    {
        unset($this->instances[$this->normalize($abstract)]);
    }
    public function forgetInstances()
    {
        $this->instances = [];
    }
    public function flush()
    {
        $this->aliases = [];
        $this->resolved = [];
        $this->bindings = [];
        $this->instances = [];
    }
    public static function getInstance()
    {
        if (is_null(static::$instance)) {
            static::$instance = new static();
        }
        return static::$instance;
    }
    public static function setInstance(ContainerContract $container = null)
    {
        return static::$instance = $container;
    }
    public function offsetExists($key)
    {
        return $this->bound($key);
    }
    public function offsetGet($key)
    {
        return $this->make($key);
    }
    public function offsetSet($key, $value)
    {
        if (!$value instanceof Closure) {
            $value = function () use($value) {
                return $value;
            };
        }
        $this->bind($key, $value);
    }
    public function offsetUnset($key)
    {
        $key = $this->normalize($key);
        unset($this->bindings[$key], $this->instances[$key], $this->resolved[$key]);
    }
    public function __get($key)
    {
        return $this[$key];
    }
    public function __set($key, $value)
    {
        $this[$key] = $value;
    }
}
}

namespace Symfony\Component\HttpKernel {
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
interface HttpKernelInterface
{
    const MASTER_REQUEST = 1;
    const SUB_REQUEST = 2;
    public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = true);
}
}

namespace Symfony\Component\HttpKernel {
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
interface TerminableInterface
{
    public function terminate(Request $request, Response $response);
}
}

