//! A serde model of the OpenAPI 3.x subset authery emits, and the options
//! that shape it. Convert into utoipa's or aide's types with
//! [`Document::convert`].

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;

/// Shapes the document. Pages are excluded and schemas are draft 2020-12
/// unless changed.
#[derive(Debug, Clone)]
pub struct OpenApiOptions {
    pub(crate) pages: bool,
    pub(crate) schema_settings: SchemaSettings,
}

impl Default for OpenApiOptions {
    fn default() -> Self {
        Self {
            pages: false,
            schema_settings: SchemaSettings::draft2020_12(),
        }
    }
}

impl OpenApiOptions {
    /// Include the HTML page routes (tagged `Pages`, `text/html`).
    pub fn with_pages(mut self, include: bool) -> Self {
        self.pages = include;
        self
    }

    /// Schema dialect. `SchemaSettings::openapi3()` gives `nullable` flags
    /// and a `3.0.3` label.
    pub fn with_schema_settings(mut self, settings: SchemaSettings) -> Self {
        self.schema_settings = settings;
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Document {
    pub openapi: String,
    pub info: Info,
    pub paths: BTreeMap<String, PathItem>,
    pub components: Components,
}

#[derive(Debug, Clone, Serialize)]
pub struct Info {
    pub title: String,
    pub version: String,
}

/// Keys are lowercase HTTP methods.
pub type PathItem = BTreeMap<String, Operation>;

#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    #[serde(rename = "operationId")]
    pub operation_id: String,
    pub tags: Vec<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Parameter>,
    #[serde(rename = "requestBody", skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBody>,
    pub responses: BTreeMap<String, Response>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security: Vec<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: &'static str,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub schema: Schema,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestBody {
    pub required: bool,
    pub content: BTreeMap<String, MediaType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MediaType {
    pub schema: Schema,
}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub description: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, Header>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub content: BTreeMap<String, MediaType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub description: String,
    pub schema: Schema,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Components {
    pub schemas: BTreeMap<String, Schema>,
    #[serde(rename = "securitySchemes")]
    pub security_schemes: BTreeMap<String, SecurityScheme>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SecurityScheme {
    ApiKey {
        name: String,
        #[serde(rename = "in")]
        location: &'static str,
    },
    Http {
        scheme: &'static str,
    },
}

impl Document {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("document serialises")
    }

    /// Deserialize into any OpenAPI model, e.g. `utoipa::openapi::OpenApi`
    /// or `aide::openapi::OpenApi`.
    ///
    /// Goes through the serialized text rather than a `Value`, because some
    /// models (aide's, for one) deserialize fields as borrowed `&str`, which
    /// a `Value` cannot hand out.
    pub fn convert<T: DeserializeOwned>(&self) -> serde_json::Result<T> {
        let json = serde_json::to_string(self)?;
        serde_json::from_str(&json)
    }
}

/// Carries the schema generator and the config facts the operations need.
pub(crate) struct Describe {
    generator: SchemaGenerator,
    pub(crate) bearer: bool,
    pub(crate) session_cookie: String,
}

/// The name of the header the cookie layer stamps on a fresh session, and
/// the words describing it - shared with the aide describer.
pub(crate) const AUTH_TOKEN_HEADER: &str = "X-Auth-Token";
pub(crate) const AUTH_TOKEN_HEADER_DESCRIPTION: &str = "Session token for `Authorization: Bearer`, present when this request \
     established a new session.";

pub(crate) const FORM: &str = "application/x-www-form-urlencoded";
pub(crate) const JSON: &str = "application/json";
pub(crate) const HTML: &str = "text/html";

impl Describe {
    pub(crate) fn new(mut settings: SchemaSettings, bearer: bool, session_cookie: String) -> Self {
        settings.definitions_path = "#/components/schemas/".into();
        Self {
            generator: SchemaGenerator::new(settings),
            bearer,
            session_cookie,
        }
    }

    /// `3.0.3` for the openapi3 preset, else `3.1.0`.
    pub(crate) fn version_label(&self) -> &'static str {
        let meta = self
            .generator
            .settings()
            .meta_schema
            .as_deref()
            .unwrap_or("");
        if meta.contains("/oas/3.0/") {
            "3.0.3"
        } else {
            "3.1.0"
        }
    }

    /// A `$ref` to `T`, registering it in components.
    pub(crate) fn schema_ref<T: JsonSchema>(&mut self) -> Schema {
        self.generator.subschema_for::<T>()
    }

    /// Both media types, one shared schema.
    pub(crate) fn body<T: JsonSchema>(&mut self) -> RequestBody {
        let schema = self.schema_ref::<T>();
        let mut content = BTreeMap::new();
        content.insert(
            FORM.to_string(),
            MediaType {
                schema: schema.clone(),
            },
        );
        content.insert(JSON.to_string(), MediaType { schema });
        RequestBody {
            required: true,
            content,
        }
    }

    /// A JSON-only body around an already-built schema.
    pub(crate) fn json_body(schema: Schema) -> RequestBody {
        RequestBody {
            required: true,
            content: BTreeMap::from([(JSON.to_string(), MediaType { schema })]),
        }
    }

    /// One query parameter per property of `T`'s inline object schema.
    pub(crate) fn query<T: JsonSchema>(&mut self) -> Vec<Parameter> {
        let schema = T::json_schema(&mut self.generator);
        let value = schema.as_value();
        let required: Vec<&str> = value["required"]
            .as_array()
            .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let mut params: Vec<Parameter> = value["properties"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, prop)| Parameter {
                name: name.clone(),
                location: "query",
                required: required.contains(&name.as_str()),
                description: prop
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(str::to_string),
                schema: Schema::try_from(prop.clone()).expect("property is a schema"),
            })
            .collect();
        params.sort_by(|a, b| a.name.cmp(&b.name));
        params
    }

    pub(crate) fn json_response<T: JsonSchema>(&mut self, description: &str) -> Response {
        let schema = self.schema_ref::<T>();
        let mut content = BTreeMap::new();
        content.insert(JSON.to_string(), MediaType { schema });
        Response {
            description: description.into(),
            headers: BTreeMap::new(),
            content,
        }
    }

    /// A JSON response around an already-built schema.
    pub(crate) fn schema_response(schema: Schema, description: &str) -> Response {
        Response {
            description: description.into(),
            headers: BTreeMap::new(),
            content: BTreeMap::from([(JSON.to_string(), MediaType { schema })]),
        }
    }

    pub(crate) fn plain_response(description: &str) -> Response {
        Response {
            description: description.into(),
            headers: BTreeMap::new(),
            content: BTreeMap::new(),
        }
    }

    pub(crate) fn html_response(description: &str) -> Response {
        let mut content = BTreeMap::new();
        content.insert(
            HTML.to_string(),
            MediaType {
                schema: schemars::json_schema!({ "type": "string" }),
            },
        );
        Response {
            description: description.into(),
            headers: BTreeMap::new(),
            content,
        }
    }

    pub(crate) fn opaque_object(description: &str) -> Schema {
        schemars::json_schema!({
            "type": "object",
            "description": description,
            "externalDocs": { "url": "https://www.w3.org/TR/webauthn-3/#iface-pkcredential" }
        })
    }

    pub(crate) fn auth_token_header(&self) -> Option<(String, Header)> {
        self.bearer.then(|| {
            (
                AUTH_TOKEN_HEADER.to_string(),
                Header {
                    description: AUTH_TOKEN_HEADER_DESCRIPTION.into(),
                    schema: schemars::json_schema!({ "type": "string" }),
                },
            )
        })
    }

    pub(crate) fn security(&self) -> Vec<BTreeMap<String, Vec<String>>> {
        let mut out = vec![BTreeMap::from([("session_cookie".to_string(), vec![])])];
        if self.bearer {
            out.push(BTreeMap::from([("bearer".to_string(), vec![])]));
        }
        out
    }

    pub(crate) fn finish(mut self, paths: BTreeMap<String, PathItem>) -> Document {
        let openapi = self.version_label().to_string();
        let mut components = Components::default();
        for (name, schema) in self.generator.take_definitions(true) {
            components.schemas.insert(
                name,
                Schema::try_from(schema).expect("definition is a schema"),
            );
        }
        components.security_schemes.insert(
            "session_cookie".into(),
            SecurityScheme::ApiKey {
                name: self.session_cookie.clone(),
                location: "cookie",
            },
        );
        if self.bearer {
            components
                .security_schemes
                .insert("bearer".into(), SecurityScheme::Http { scheme: "bearer" });
        }
        Document {
            openapi,
            info: Info {
                title: "Authery".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            paths,
            components,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::JsonSchema;

    #[derive(JsonSchema)]
    #[allow(dead_code)]
    struct Q {
        /// The next page.
        next: Option<String>,
        code: String,
    }

    #[test]
    fn query_parameters_come_from_the_schema() {
        let mut describe =
            Describe::new(SchemaSettings::draft2020_12(), false, "session_id".into());
        let params = describe.query::<Q>();
        let names: Vec<_> = params
            .iter()
            .map(|p| (p.name.as_str(), p.required))
            .collect();
        assert_eq!(names, [("code", true), ("next", false)]);
        assert_eq!(params[1].description.as_deref(), Some("The next page."));
    }
}
