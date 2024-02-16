package otoroshi_plugins.com.cloud.apim.plugins.curity

import com.github.blemale.scaffeine.{Cache, Scaffeine}
import otoroshi.env.Env
import otoroshi.gateway.Errors
import otoroshi.models.{ApiKey, RouteIdentifier}
import otoroshi.next.plugins.api._
import otoroshi.utils.syntax.implicits.{BetterJsReadable, BetterJsValue, BetterSyntax}
import play.api.libs.json._
import play.api.libs.typedmap.TypedKey
import play.api.libs.ws.DefaultBodyWritables.writeableOf_urlEncodedSimpleForm
import play.api.mvc.Results

import java.util.concurrent.TimeUnit
import scala.concurrent.duration.{DurationInt, FiniteDuration}
import scala.concurrent.{ExecutionContext, Future, Promise}
import scala.util.{Failure, Success, Try}

case class CurityPhantomTokenValidatorConfig(introspectionUrl: String, clientId: String, clientSecret: String, ttl: FiniteDuration) extends NgPluginConfig {
  def json: JsValue = CurityPhantomTokenValidatorConfig.format.writes(this)
}

object CurityPhantomTokenValidatorConfig {
  val default = CurityPhantomTokenValidatorConfig(
    introspectionUrl = "https://localhost:8443/introspection",
    clientId = "client",
    clientSecret = "secret",
    ttl = 10.minutes,
  )
  val format = new Format[CurityPhantomTokenValidatorConfig] {
    override def reads(json: JsValue): JsResult[CurityPhantomTokenValidatorConfig] = Try {
      CurityPhantomTokenValidatorConfig(
        introspectionUrl = json.select("introspection_url").asString,
        clientId = json.select("client_id").asString,
        clientSecret = json.select("client_secret").asString,
        ttl = json.select("ttl").asOpt[Long].map(m => FiniteDuration(m, TimeUnit.MILLISECONDS)).getOrElse(10.minutes),
      )
    } match {
      case Failure(e) => JsError(e.getMessage)
      case Success(s) => JsSuccess(s)
    }
    override def writes(o: CurityPhantomTokenValidatorConfig): JsValue = Json.obj(
      "introspection_url" -> o.introspectionUrl,
      "client_id" -> o.clientId,
      "client_secret" -> o.clientSecret,
      "ttl" -> o.ttl.toMillis,
    )
  }
}

sealed trait CurityPhantomTokenState {}
object CurityPhantomTokenState {
  case class CurityPhantomTokenFetching(promise: Promise[NgAccess]) extends CurityPhantomTokenState
  case class CurityPhantomTokenValid(content: JsValue) extends CurityPhantomTokenState
  case class CurityPhantomTokenInvalid() extends CurityPhantomTokenState
}
case class CurityPhantomTokenStateWrapper(ttl: FiniteDuration, state: CurityPhantomTokenState)


object CurityPhantomTokenValidator {
  val PhantomTokenKey = TypedKey[JsValue]("com.cloud-apim.plugins.curity.PhantomTokenKey")
}

class CurityPhantomTokenValidator extends NgAccessValidator {

  private val tokenCache: Cache[String, CurityPhantomTokenStateWrapper] = Scaffeine()
    .expireAfter[String, CurityPhantomTokenStateWrapper](
      create = (key, value) => value.ttl,
      update =  (key, value, currentDuration) => value.ttl,
      read = (key, value, currentDuration) => currentDuration
    )
    .maximumSize(5000)
    .build()

  override def steps: Seq[NgStep]                = Seq(NgStep.ValidateAccess)
  override def categories: Seq[NgPluginCategory] = Seq(NgPluginCategory.AccessControl)
  override def visibility: NgPluginVisibility    = NgPluginVisibility.NgUserLand

  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = true
  override def isAccessAsync: Boolean                      = true
  override def name: String                                = "Cloud APIM - Curity Phantom Token validator"
  override def description: Option[String]                 =
    "This plugin tries to validate curity phantom token against a curity idp server".some
  override def defaultConfigObject: Option[NgPluginConfig] = CurityPhantomTokenValidatorConfig.default.some

  def noJsForm: Boolean = true

  override def configFlow: Seq[String] = Seq(
    "introspection_url",
    "client_id",
    "client_secret",
    "ttl",
  )

  override def configSchema: Option[JsObject] = Some(Json.obj(
    "introspection_url" -> Json.obj(
      "type" -> "string",
      "label" -> "Curity introspection url",
    ),
    "client_id" -> Json.obj(
      "type" -> "string",
      "label" -> "Curity client_id",
    ),
    "client_secret" -> Json.obj(
      "type" -> "string",
      "label" -> "Curity client_secret",
    ),
    "ttl" -> Json.obj(
      "type" -> "number",
      "label" -> "Token validation TTL",
    )
  ))

  def unauthorized(ctx: NgAccessContext)(implicit env: Env, ec: ExecutionContext): Future[NgAccess] = {
    Errors
      .craftResponseResult(
        "unauthorized",
        Results.Unauthorized,
        ctx.request,
        None,
        None,
        duration = ctx.report.getDurationNow(),
        overhead = ctx.report.getOverheadInNow(),
        attrs = ctx.attrs,
        maybeRoute = ctx.route.some
      )
      .map(r => NgAccess.NgDenied(r))
  }

  def start(env: Env): Future[Unit] = {
    env.logger.info("[Cloud APIM] the 'Curity Phantom Token validator' plugin is available !")
    ().vfuture
  }

  override def access(ctx: NgAccessContext)(implicit env: Env, ec: ExecutionContext): Future[NgAccess] = {
    val config =
      ctx.cachedConfig(internalName)(CurityPhantomTokenValidatorConfig.format).getOrElse(CurityPhantomTokenValidatorConfig.default)
    ctx.request.headers.get("Authorization") match {
      case Some(value) if value.startsWith("Bearer ") => {
        val token = value.substring(7)
        tokenCache.getIfPresent(token) match {
          case Some(CurityPhantomTokenStateWrapper(_, CurityPhantomTokenState.CurityPhantomTokenFetching(promise))) => promise.future
          case Some(CurityPhantomTokenStateWrapper(_, CurityPhantomTokenState.CurityPhantomTokenValid(content))) => {
            ctx.attrs.put(CurityPhantomTokenValidator.PhantomTokenKey -> content)
            val user = ApiKey(
              clientId = token,
              clientSecret = token,
              clientName = token,
              authorizedEntities = Seq(RouteIdentifier(ctx.route.id)),
              metadata = Map("content" -> content.stringify)
            )
            ctx.attrs.put(otoroshi.plugins.Keys.ApiKeyKey -> user)
            NgAccess.NgAllowed.vfuture
          }
          case Some(CurityPhantomTokenStateWrapper(_, CurityPhantomTokenState.CurityPhantomTokenInvalid())) => unauthorized(ctx)
          case None => {
            val promise = Promise[NgAccess]()
            tokenCache.put(token, CurityPhantomTokenStateWrapper(config.ttl, CurityPhantomTokenState.CurityPhantomTokenFetching(promise)))
            env.Ws
              .url(config.introspectionUrl)
              .withFollowRedirects(true)
              .withRequestTimeout(10.seconds)
              .withHttpHeaders(
                "cache-control" -> "no-cache"
              )
              .post(Map(
                "client_id" -> config.clientId,
                "client_secret" -> config.clientSecret,
                "token" -> token,
              ))(writeableOf_urlEncodedSimpleForm)
              .flatMap { resp =>
                if (resp.status == 200) {
                  tokenCache.put(token, CurityPhantomTokenStateWrapper(config.ttl, CurityPhantomTokenState.CurityPhantomTokenValid(resp.json)))
                  promise.trySuccess(NgAccess.NgAllowed)
                  NgAccess.NgAllowed.vfuture
                } else {
                  tokenCache.put(token, CurityPhantomTokenStateWrapper(config.ttl, CurityPhantomTokenState.CurityPhantomTokenInvalid()))
                  unauthorized(ctx).map { r =>
                    promise.trySuccess(r)
                    r
                  }
                }
              }
          }
        }
      }
      case None => unauthorized(ctx)
    }
  }
}
