"""Confidence-guided Protocol IR modeling pipeline.

This package contains the local IR review, Sapic+/Tamarin generation, and
verification helpers used by the public review UI.
"""

from .c_to_ir import build_c_code_context, run_c_to_ir_extraction
from .pipeline import PipelineConfig, ProtocolIRPipeline

__all__ = ["PipelineConfig", "ProtocolIRPipeline", "build_c_code_context", "run_c_to_ir_extraction"]
