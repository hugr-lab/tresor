#include "tresor_catalog.hpp"
#include "tresor_extension.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/settings.hpp"

// corp.secrets() (specs/004): what the caller may see in the service and what it may do with each -
// descriptors, never material. And tresor_secret_param(): a diagnostic - a secret's parameter as DuckDB
// holds it, with its type; only where unredacted secrets may be shown at all, and never a redacted key's
// value.

namespace duckdb {
namespace tresor {

namespace {

struct SecretsBindData : public TableFunctionData {
	explicit SecretsBindData(TresorSecretStorage &storage_p) : storage(storage_p) {
	}
	TresorSecretStorage &storage;
};

struct SecretsState : public GlobalTableFunctionState {
	vector<Descriptor> rows;
	idx_t offset = 0;
	bool fetched = false;
};

unique_ptr<FunctionData> SecretsBind(ClientContext &context, TableFunctionBindInput &input,
                                     vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto &info = input.info->Cast<TresorFunctionInfo>();
	auto add = [&](const char *name, LogicalType type) {
		names.emplace_back(name);
		return_types.push_back(std::move(type));
	};
	add("name", LogicalType::VARCHAR);
	add("type", LogicalType::VARCHAR);
	add("provider", LogicalType::VARCHAR);
	add("scope", LogicalType::LIST(LogicalType::VARCHAR));
	add("comment", LogicalType::VARCHAR);
	add("owner", LogicalType::VARCHAR);
	add("permissions", LogicalType::LIST(LogicalType::VARCHAR));
	add("dynamic", LogicalType::BOOLEAN);
	add("updated_at", LogicalType::TIMESTAMP_TZ);
	add("version", LogicalType::VARCHAR);
	return make_uniq<SecretsBindData>(*info.storage);
}

unique_ptr<GlobalTableFunctionState> SecretsInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<SecretsState>();
}

Value Strings(const vector<string> &items) {
	vector<Value> values;
	for (auto &item : items) {
		values.emplace_back(item);
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(values));
}

Value TimestampOrNull(const string &text) {
	timestamp_t parsed;
	if (!text.empty() &&
	    Timestamp::TryConvertTimestamp(text.c_str(), text.size(), parsed, true) == TimestampCastResult::SUCCESS) {
		return Value::TIMESTAMPTZ(timestamp_tz_t(parsed));
	}
	return Value(LogicalType::TIMESTAMP_TZ);
}

void SecretsScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<SecretsState>();
	if (!state.fetched) {
		state.rows = data.bind_data->Cast<SecretsBindData>().storage.Refresh(); // always the service's current state
		state.fetched = true;
	}
	idx_t count = 0;
	while (state.offset < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &d = state.rows[state.offset++];
		output.data[0].Append(Value(d.name));
		output.data[1].Append(Value(d.type));
		output.data[2].Append(Value(d.provider));
		output.data[3].Append(Strings(d.scope));
		output.data[4].Append(d.comment.empty() ? Value(LogicalType::VARCHAR) : Value(d.comment));
		output.data[5].Append(Value(d.owner));
		output.data[6].Append(Strings(d.permissions));
		output.data[7].Append(Value::BOOLEAN(d.dynamic));
		output.data[8].Append(TimestampOrNull(d.updated_at));
		output.data[9].Append(Value(d.version));
		count++;
	}
}

void SecretParamFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	if (!Settings::Get<AllowUnredactedSecretsSetting>(context)) {
		throw InvalidInputException("tresor_secret_param: showing secret parameters is disabled "
		                            "(allow_unredacted_secrets = false)");
	}
	auto &manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	for (idx_t row = 0; row < args.size(); row++) {
		auto name = args.data[0].GetValue(row);
		auto key = args.data[1].GetValue(row);
		if (name.IsNull() || key.IsNull()) {
			result.SetValue(row, Value(LogicalType::VARCHAR));
			continue;
		}
		auto entry = manager.GetSecretByName(transaction, name.ToString());
		if (!entry) {
			throw InvalidInputException("tresor_secret_param: no secret named '%s'", name.ToString());
		}
		auto key_value = dynamic_cast<const KeyValueSecret *>(entry->secret.get());
		auto found = key_value ? key_value->secret_map.find(Identifier(StringUtil::Lower(key.ToString())))
		                       : identifier_tree_t<Value>::const_iterator();
		if (!key_value || found == key_value->secret_map.end()) {
			result.SetValue(row, Value(LogicalType::VARCHAR));
			continue;
		}
		// the value as DuckDB holds it, with its type: 'INTEGER 1433', 'MAP(VARCHAR, VARCHAR) {X-Tenant=sales}';
		// a redacted key shows its type only - this is a diagnostic, not a way around redaction
		auto shown = key_value->redact_keys.count(found->first) ? string("<redacted>") : found->second.ToString();
		result.SetValue(row, Value(found->second.type().ToString() + " " + shown));
	}
}

} // namespace

TableFunction SecretsFunction(shared_ptr<TresorSession> session, TresorSecretStorage &storage) {
	TableFunction function(Identifier("secrets"), {}, SecretsScan, SecretsBind, SecretsInit);
	function.function_info = make_shared_ptr<TresorFunctionInfo>(std::move(session), &storage);
	return function;
}

} // namespace tresor

void RegisterTresorSecretParam(ExtensionLoader &loader) {
	ScalarFunction fun(Identifier("tresor_secret_param"), {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                   LogicalType::VARCHAR, tresor::SecretParamFun);
	fun.SetVolatile();
	fun.SetFallible(); // it refuses (a disabled setting, an unknown or unusable secret) by throwing
	loader.RegisterFunction(fun);
}

} // namespace duckdb
