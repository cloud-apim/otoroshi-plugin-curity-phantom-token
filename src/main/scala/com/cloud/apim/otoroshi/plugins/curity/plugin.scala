package otoroshi_plugins.com.cloud.apim.plugins.curity

import com.github.blemale.scaffeine.{Cache, Scaffeine}
import otoroshi.env.Env
import otoroshi.gateway.Errors
import otoroshi.models.{ApiKey, RouteIdentifier}
import otoroshi.next.plugins.api.*
import otoroshi.utils.syntax.implicits.{BetterJsReadable, BetterJsValue, BetterSyntax}
import play.api.libs.json.*
import play.api.libs.typedmap.TypedKey
import play.api.libs.ws.DefaultBodyWritables.writeableOf_urlEncodedSimpleForm
import play.api.mvc.{RequestHeader, Results}

import java.util.concurrent.TimeUnit
import scala.concurrent.duration.{DurationInt, FiniteDuration}
import scala.concurrent.{ExecutionContext, Future, Promise}
import scala.util.{Failure, Success, Try}

private val BearerPrefix = "Bearer "

extension (req: RequestHeader) {
  private def phantomToken: Option[String] = req.headers
    .get("Authorization")
    .filter(_.startsWith(BearerPrefix))
    .map(_.drop(BearerPrefix.length))
}

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
  given format: Format[CurityPhantomTokenValidatorConfig] = new Format[CurityPhantomTokenValidatorConfig] {
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

enum CurityPhantomTokenState {
  case Fetching(promise: Promise[NgAccess])
  case Valid(content: JsValue)
  case Invalid
}

case class CurityPhantomTokenStateWrapper(ttl: FiniteDuration, state: CurityPhantomTokenState)


object CurityPhantomTokenValidator {
  val PhantomTokenKey = TypedKey[JsValue]("com.cloud-apim.plugins.curity.PhantomTokenKey")
}

class CurityPhantomTokenValidator extends NgAccessValidator {

  private val tokenCache: Cache[String, CurityPhantomTokenStateWrapper] = Scaffeine()
    .expireAfter[String, CurityPhantomTokenStateWrapper](
      create = (_, value) => value.ttl,
      update = (_, value, _) => value.ttl,
      read = (_, _, currentDuration) => currentDuration
    )
    .maximumSize(5000)
    .build()

  override def steps: Seq[NgStep]                = Seq(NgStep.ValidateAccess)
  override def categories: Seq[NgPluginCategory] = Seq(NgPluginCategory.AccessControl, NgPluginCategory.Custom("Cloud APIM"))
  override def visibility: NgPluginVisibility    = NgPluginVisibility.NgUserLand

  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = true
  override def isAccessAsync: Boolean                      = true
  override def name: String                                = "Cloud APIM - Curity Phantom Token validator"
  override def description: Option[String]                 =
    "This plugin tries to validate curity phantom token against a curity idp server".some
  override def defaultConfigObject: Option[NgPluginConfig] = CurityPhantomTokenValidatorConfig.default.some

  override def noJsForm: Boolean = true

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

  def unauthorized(ctx: NgAccessContext)(using env: Env, ec: ExecutionContext): Future[NgAccess] = {
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

  override def start(env: Env): Future[Unit] = {
    env.logger.info("[Cloud APIM] the 'Curity Phantom Token validator' plugin is available !")
    ().vfuture
  }

  override def access(ctx: NgAccessContext)(using env: Env, ec: ExecutionContext): Future[NgAccess] = {
    val config =
      ctx.cachedConfig(internalName)(CurityPhantomTokenValidatorConfig.format).getOrElse(CurityPhantomTokenValidatorConfig.default)
    ctx.request.phantomToken match {
      case None => unauthorized(ctx)
      case Some(token) => {
        tokenCache.getIfPresent(token) match {
          case Some(CurityPhantomTokenStateWrapper(_, CurityPhantomTokenState.Fetching(promise))) => promise.future
          case Some(CurityPhantomTokenStateWrapper(_, CurityPhantomTokenState.Valid(content))) => {
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
          case Some(CurityPhantomTokenStateWrapper(_, CurityPhantomTokenState.Invalid)) => unauthorized(ctx)
          case None => {
            val promise = Promise[NgAccess]()
            tokenCache.put(token, CurityPhantomTokenStateWrapper(config.ttl, CurityPhantomTokenState.Fetching(promise)))
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
              ))(using writeableOf_urlEncodedSimpleForm)
              .flatMap { resp =>
                if (resp.status == 200) {
                  tokenCache.put(token, CurityPhantomTokenStateWrapper(config.ttl, CurityPhantomTokenState.Valid(resp.json)))
                  promise.trySuccess(NgAccess.NgAllowed)
                  NgAccess.NgAllowed.vfuture
                } else {
                  tokenCache.put(token, CurityPhantomTokenStateWrapper(config.ttl, CurityPhantomTokenState.Invalid))
                  unauthorized(ctx).map { r =>
                    promise.trySuccess(r)
                    r
                  }
                }
              }
          }
        }
      }
    }
  }
}
