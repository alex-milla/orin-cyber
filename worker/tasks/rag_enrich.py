"""
Tarea rag_enrich: dado un objeto entity (IP, hash, subject, descripción incidente),
busca casos similares vía embeddings + sqlite-vec, llama al LLM con esos casos
como contexto, y devuelve un JSON con veredicto, score, recomendación y KQL.
"""
import json
import logging
from typing import Dict, Any, List

from tasks.base import BaseTask
from utils.embeddings import EmbeddingClient
from utils.llm_client import LlmClient
from utils.api_client import ApiClient

logger = logging.getLogger(__name__)


class RagEnrichTask(BaseTask):
    task_type = "rag_enrich"

    def __init__(self, config_path: str = None):
        self.embed_client = EmbeddingClient()
        self.llm = LlmClient(config_path)
        self.api = ApiClient(config_path)

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Ejecuta el enriquecimiento RAG para una o más entidades.
        Si input_data contiene 'batch', procesa en lote.
        """
        if input_data.get("batch"):
            return self._execute_batch(input_data["batch"])
        return self._execute_single(input_data)

    def _execute_single(self, input_data: Dict[str, Any]) -> Dict[str, str]:
        entity = input_data.get("entity", input_data)
        options = input_data.get("options", {})
        k = min(int(options.get("k", 5)), 10)
        language = options.get("language", "es")
        include_kql = options.get("include_kql_hunting", False)

        # 1. Buscar casos similares via API del hosting
        similar = self.api.search_similar_incidents(entity=entity, k=k)

        # 2. Construir prompt para el LLM
        prompt = self._build_prompt(entity, similar, language)

        # 3. Llamar al LLM con respuesta JSON estructurada
        llm_response = self.llm.chat_json(
            system_prompt=self._system_prompt(language),
            user_prompt=prompt,
            max_tokens=800,
        )

        if not llm_response:
            logger.warning("LLM returned empty/invalid JSON, falling back")
            llm_response = self._fallback_response(entity, similar)

        # 4. Construir resultado enriquecido
        result = {
            "verdict": llm_response.get("verdict", "inconclusive"),
            "score": float(llm_response.get("score", 0.5)),
            "confidence": llm_response.get("confidence", "medium"),
            "similar_cases": [
                {
                    "incident_id": c.get("incident_id"),
                    "similarity": round(c.get("similarity", 0), 3),
                    "summary": c.get("summary", "")[:200],
                    "verdict": c.get("verdict"),
                    "closed_at": c.get("closed_at"),
                }
                for c in similar[:k]
            ],
            "recommendation": llm_response.get("recommendation", ""),
            "mitre_tactic": llm_response.get("mitre_tactic"),
            "mitre_technique": llm_response.get("mitre_technique"),
            "kql_hunting": self._generate_kql(entity, llm_response) if include_kql else None,
        }

        result_json = json.dumps(result, ensure_ascii=False)
        result_html = self._render_html(result, entity)

        return {
            "result_html": result_html,
            "result_text": result_json,
        }

    def _execute_batch(self, batch: List[Dict[str, Any]]) -> Dict[str, str]:
        """Procesa un lote de entidades en una sola llamada LLM."""
        entities = [b.get("entity", b) for b in batch]
        options = batch[0].get("options", {}) if batch else {}
        k = min(int(options.get("k", 3)), 10)
        language = options.get("language", "es")

        # Buscar similares para cada entidad
        similar_map = {}
        for i, ent in enumerate(entities):
            try:
                similar_map[i] = self.api.search_similar_incidents(ent, k=k)
            except Exception as e:
                logger.warning("Error buscando similares para entidad %s: %s", i, e)
                similar_map[i] = []

        # Prompt batch
        prompt = self._build_batch_prompt(entities, similar_map, language)

        llm_response = self.llm.chat_json(
            system_prompt=self._system_prompt_batch(language),
            user_prompt=prompt,
            max_tokens=2000,
        )

        results = llm_response.get("results", []) if llm_response else []
        if not results:
            # Fallback individual
            results = [self._fallback_response(ent, similar_map.get(i, [])) for i, ent in enumerate(entities)]

        combined = {
            "results": results,
            "batch_size": len(entities),
        }
        result_json = json.dumps(combined, ensure_ascii=False)

        return {
            "result_html": f"<pre>{result_json}</pre>",
            "result_text": result_json,
        }

    def _system_prompt(self, lang: str) -> str:
        if lang == "es":
            return (
                "Eres un analista SOC senior. Recibirás una entidad sospechosa "
                "y casos similares previos del entorno. Devuelve SOLO JSON válido "
                "con: verdict (likely_true_positive|likely_false_positive|inconclusive), "
                "score (0-1), confidence (low|medium|high), recommendation (texto breve), "
                "mitre_tactic, mitre_technique. Basa tu juicio en los casos previos."
            )
        return (
            "You are a senior SOC analyst. You'll receive a suspicious entity "
            "and similar prior cases from the environment. Return ONLY valid JSON "
            "with: verdict, score (0-1), confidence, recommendation, mitre_tactic, "
            "mitre_technique. Base your judgment on prior cases."
        )

    def _system_prompt_batch(self, lang: str) -> str:
        if lang == "es":
            return (
                "Eres un analista SOC senior. Recibirás múltiples entidades sospechosas "
                "y sus casos similares previos. Devuelve SOLO JSON válido con clave 'results' "
                "que sea una lista de objetos, uno por entidad, cada uno con: "
                "verdict, score, confidence, recommendation, mitre_tactic, mitre_technique."
            )
        return (
            "You are a senior SOC analyst. You'll receive multiple suspicious entities "
            "and their similar prior cases. Return ONLY valid JSON with key 'results' "
            "as a list of objects, one per entity, each with: "
            "verdict, score, confidence, recommendation, mitre_tactic, mitre_technique."
        )

    def _build_prompt(self, entity: Dict, similar: List[Dict], lang: str) -> str:
        ent_text = json.dumps(entity, ensure_ascii=False, indent=2)
        if not similar:
            cases_text = "(sin casos similares en el histórico)"
        else:
            cases_text = "\n\n".join([
                f"Caso #{i+1} (similitud {c.get('similarity', 0):.2f}, veredicto {c.get('verdict', '—')}, "
                f"cerrado {c.get('closed_at', '—')}):\n{c.get('summary', '')}"
                for i, c in enumerate(similar)
            ])

        return f"""ENTIDAD A ANALIZAR:
{ent_text}

CASOS SIMILARES PREVIOS DEL ENTORNO:
{cases_text}

Analiza la entidad considerando el patrón histórico. Responde JSON."""

    def _build_batch_prompt(self, entities: List[Dict], similar_map: Dict[int, List[Dict]], lang: str) -> str:
        parts = []
        for i, ent in enumerate(entities):
            ent_text = json.dumps(ent, ensure_ascii=False, indent=2)
            similar = similar_map.get(i, [])
            if not similar:
                cases_text = "(sin casos similares)"
            else:
                cases_text = "\n".join([
                    f"  - Caso #{j+1} (sim {c.get('similarity', 0):.2f}, {c.get('verdict', '—')}): {c.get('summary', '')[:150]}"
                    for j, c in enumerate(similar)
                ])
            parts.append(f"--- ENTIDAD #{i+1} ---\n{ent_text}\nCasos similares:\n{cases_text}")

        return "\n\n".join(parts) + "\n\nAnaliza cada entidad. Responde JSON con clave 'results'."

    def _fallback_response(self, entity, similar):
        if not similar:
            return {
                "verdict": "inconclusive",
                "score": 0.5,
                "confidence": "low",
                "recommendation": "Sin histórico previo. Investigar manualmente.",
            }
        verdicts = [c.get("verdict") for c in similar if c.get("verdict")]
        tp = verdicts.count("TP")
        fp = verdicts.count("FP")
        if fp > tp * 2:
            v = "likely_false_positive"
        elif tp > fp:
            v = "likely_true_positive"
        else:
            v = "inconclusive"
        return {
            "verdict": v,
            "score": 0.6,
            "confidence": "medium",
            "recommendation": f"{len(similar)} casos similares: {tp} TP / {fp} FP",
        }

    def _generate_kql(self, entity, llm_response):
        ent_type = entity.get("type", "")
        ent_value = entity.get("value", "")
        if ent_type == "ip":
            return f"""SecurityEvent
| where TimeGenerated > ago(7d)
| where IpAddress == "{ent_value}"
| project TimeGenerated, EventID, Computer, Account, IpAddress"""
        if ent_type == "hash":
            return f"""DeviceFileEvents
| where TimeGenerated > ago(30d)
| where SHA256 == "{ent_value}"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName"""
        if ent_type == "domain":
            return f"""DnsEvents
| where TimeGenerated > ago(7d)
| where Name contains "{ent_value}"
| summarize count() by Computer, Name"""
        return None

    def _render_html(self, result: Dict, entity: Dict) -> str:
        similar = result.get("similar_cases", [])
        similar_html = ""
        if similar:
            rows = "\n".join([
                f"<tr><td>#{c.get('incident_id', '—')}</td>"
                f"<td>{c.get('similarity', 0):.2f}</td>"
                f"<td>{c.get('verdict', '—')}</td>"
                f"<td>{c.get('summary', '')}</td></tr>"
                for c in similar
            ])
            similar_html = f"""
            <h4>Casos similares</h4>
            <table border='1' cellpadding='4'><tr><th>ID</th><th>Sim</th><th>Veredicto</th><th>Resumen</th></tr>
            {rows}</table>"""

        kql = result.get("kql_hunting")
        kql_html = f"<h4>KQL Hunting</h4><pre>{kql}</pre>" if kql else ""

        return f"""
        <div style="font-family:sans-serif;max-width:800px;">
        <h3>🔍 Enriquecimiento RAG</h3>
        <p><strong>Entidad:</strong> {entity.get('type', '—')} — {entity.get('value', entity.get('subject', '—'))}</p>
        <p><strong>Veredicto:</strong> {result.get('verdict', '—')} | <strong>Score:</strong> {result.get('score', 0)} | <strong>Confianza:</strong> {result.get('confidence', '—')}</p>
        <p><strong>Recomendación:</strong> {result.get('recommendation', '—')}</p>
        {similar_html}
        {kql_html}
        </div>
        """
