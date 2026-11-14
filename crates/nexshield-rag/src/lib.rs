//! nexshield-rag: Retrieval-Augmented Generation (RAG) cybersecurity knowledge and advisory engine.

pub mod knowledge;

pub use knowledge::{KnowledgeChunk, RagCorpusStats, RagEngine, SECURITY_KNOWLEDGE_BASE};
