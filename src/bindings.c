/**
 *  Copyright (C) 2021  Peter Kohler
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <libguile.h>
#include <gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <stdint.h>

#define INSTATHROW(symbol) return scm_throw(\
    scm_from_utf8_symbol(symbol),\
    scm_list_1(SCM_UNDEFINED))
#define INSTATHROW_SCM(symbol, obj) return scm_throw(\
  scm_from_utf8_symbol(symbol),\
  obj)
#define INSTATHROW_WHY(symbol, reason)\
  INSTATHROW_SCM(symbol, scm_list_1(scm_from_utf8_string(reason)))

/**
 * Describes mechanism-specific minor status codes
 */
SCM describe_minor_status(OM_uint32 minor_status, gss_OID mechanism)
{
  if (mechanism != gss_mech_krb5)
    return scm_list_1(scm_from_utf8_symbol("unknown_mechanism"));

  OM_uint32 maj_status, min_status;
  OM_uint32 message_context = 0;
  gss_buffer_desc status_string;
  
  SCM message_list = scm_list_n(SCM_UNDEFINED);
  do
    {
  
      maj_status = gss_display_status(&min_status
				      ,minor_status
				      ,GSS_C_MECH_CODE
				      ,mechanism
				      ,&message_context
				      ,&status_string);

      SCM msg;
      if (GSS_ERROR(maj_status))
	{
	  msg = scm_from_utf8_string("<error looking up next message>");
	  message_context = 0;
	}
      else
	{
	  msg = scm_c_make_bytevector(status_string.length);
	  memcpy(SCM_BYTEVECTOR_CONTENTS(msg)
		 ,status_string.value
		 ,status_string.length);
	  msg = scm_utf8_to_string(msg);
	}

      message_list = scm_cons(msg, message_list);
    }
  while (message_context != 0);

  return scm_list_2(scm_from_utf8_symbol("krb5")
		    ,message_list);
  //scm_from_uint32(minor_status));
}

/**
 * Checks the major & minor status codes for errors.
 * 
 * Returns SCM_UNDEFINED if all is well, or an exception otherwise.
 */
#define HANDLE_GSS_ERROR(major, minor, optional_mech) { SCM result = check_for_gss_error(major, minor, optional_mech); if (result != SCM_UNDEFINED) return result; }
SCM check_for_gss_error(OM_uint32 major_status, OM_uint32 minor_status, const gss_OID *optional_mech)
{
  if (!GSS_ERROR(major_status))
    return SCM_UNDEFINED;

  // Okay, we have an error
  SCM calling_error = scm_from_utf8_symbol("no_calling_error");
  switch(GSS_CALLING_ERROR(major_status))
    {
    case 0:
      break;
    case GSS_S_CALL_INACCESSIBLE_READ:
      calling_error = scm_from_utf8_symbol("inaccessible_read");
      break;
    case GSS_S_CALL_INACCESSIBLE_WRITE:
      calling_error = scm_from_utf8_symbol("inaccessible_write");
      break;
    case GSS_S_CALL_BAD_STRUCTURE:
      calling_error = scm_from_utf8_symbol("bad_structure");
      break;
    default:
      calling_error = scm_list_2(scm_from_utf8_symbol("calling_error")
				 ,scm_from_uint32(GSS_CALLING_ERROR(major_status)));
      break;
    }

  SCM routine_error = scm_from_utf8_symbol("no_routine_error");
  switch(GSS_ROUTINE_ERROR(major_status))
    {
    case GSS_S_BAD_MECH:
      routine_error = scm_from_utf8_symbol("bad_mechanism");
      break;
    case GSS_S_BAD_NAME:
      routine_error = scm_from_utf8_symbol("bad_name");
      break;
    case GSS_S_BAD_NAMETYPE:
      routine_error = scm_from_utf8_symbol("bad_nametype");
      break;
    case GSS_S_BAD_BINDINGS:
      routine_error = scm_from_utf8_symbol("bad_bindings");
      break;
    case GSS_S_BAD_STATUS:
      routine_error = scm_from_utf8_symbol("bad_status");
      break;
    case GSS_S_BAD_MIC: // Same as GSS_BAD_SIG
      routine_error = scm_from_utf8_symbol("bad_mic/signature");
      break;
    case GSS_S_NO_CRED:
      routine_error = scm_from_utf8_symbol("no_available_credentials");
      break;
    case GSS_S_NO_CONTEXT:
      routine_error = scm_from_utf8_symbol("no_context");      
      break;
    case GSS_S_DEFECTIVE_TOKEN:
      routine_error = scm_from_utf8_symbol("defective_token");
      break;
    case GSS_S_DEFECTIVE_CREDENTIAL:
      routine_error = scm_from_utf8_symbol("defective_credential");
      break;
    case GSS_S_CREDENTIALS_EXPIRED:
      routine_error = scm_from_utf8_symbol("credentials_expired");
      break;
    case GSS_S_CONTEXT_EXPIRED:
      routine_error = scm_from_utf8_symbol("context_expired");
      break;
    case GSS_S_FAILURE:
      if (optional_mech != NULL)
	{
	  routine_error = scm_list_2(scm_from_utf8_symbol("failure")
				     ,describe_minor_status(minor_status, *optional_mech));
	}
      else
	{
	  routine_error = scm_from_utf8_symbol("failure");
	}
      break;
    case GSS_S_BAD_QOP:
      routine_error = scm_from_utf8_symbol("bad_qop");
      break;
    case GSS_S_UNAUTHORIZED:
      routine_error = scm_from_utf8_symbol("unauthorized");
      break;
    case GSS_S_UNAVAILABLE:
      routine_error = scm_from_utf8_symbol("unavailable");
      break;
    case GSS_S_DUPLICATE_ELEMENT:
      routine_error = scm_from_utf8_symbol("duplicate_element");
      break;
    case GSS_S_NAME_NOT_MN:
      routine_error = scm_from_utf8_symbol("name_not_mn");
      break;
    default:
      routine_error = scm_list_2(scm_from_utf8_symbol("routine_error")
				 ,scm_from_uint32(GSS_ROUTINE_ERROR(major_status)));
    }

  /* SCM supplementary_info; */
  /* switch(GSS_SUPPLEMENTARY_INFO(major_status)) */
  /*   { */
  /*   case GSS_S_CONTINUE_NEEDED: */
  /*     break; */
  /*   case GSS_S_OLD_TOKEN: */
  /*     INSTATHROW("old_token"); */
  /*   case GSS_S_DUPLICATE_TOKEN: */
  /*     INSTATHROW("duplicate_token"); */
  /*   default: */
  /*     INSTATHROW_SCM("internal_error" */
  /* 		     , scm_list_2(scm_from_uint32(major_status) */
  /* 				  ,scm_from_uint32(minor_status))); */
  /*   } */

      //  return scm_throw(scm_from_utf8_symbol("gssapi")
  //	   ,scm_list_1(SCM_UNDEFINED));
		
  return scm_throw(scm_from_utf8_symbol("gssapi")
		   ,scm_list_2(calling_error
			       ,routine_error));
}


SCM gss_name_type;			 
static void
gss_name_finalizer(SCM obj)
{
  scm_assert_foreign_object_type(gss_name_type, obj);

  gss_name_t *name = (gss_name_t*) scm_foreign_object_ref(obj, 0);

  OM_uint32 minor_status;
  gss_release_name(&minor_status, name);
}

SCM gss_oid_type;
SCM_GLOBAL_VARIABLE_INIT(gss_oid_GSS_KRB5_NT_PRINCIPAL_NAME
			 ,"GSS_KRB5_NT_PRINCIPAL_NAME"
			 ,scm_make_foreign_object_1(gss_oid_type, (void*) &GSS_KRB5_NT_PRINCIPAL_NAME));
SCM_GLOBAL_VARIABLE_INIT(gss_oid_GSS_MECH_KRB5
			 ,"GSS_MECH_KRB5"
			 ,scm_make_foreign_object_1(gss_oid_type, (void*) &gss_mech_krb5));
SCM_DEFINE(fresh_gss_oid_tolist, "oid->list", 1, 0, 0, (SCM oid), "")
{
  scm_assert_foreign_object_type(gss_oid_type, oid);

  if (scm_is_eq(oid, scm_variable_ref(gss_oid_GSS_KRB5_NT_PRINCIPAL_NAME)))
    {
      return scm_list_n(scm_from_unsigned_integer(1) // iso(1)
			,scm_from_unsigned_integer(2) // member-body(2)
			,scm_from_unsigned_integer(840) // United States(840)
			,scm_from_unsigned_integer(113554) // mit(113554)
			,scm_from_unsigned_integer(1) // infosys(1)
			,scm_from_unsigned_integer(2) // gssapi(2)
			,scm_from_unsigned_integer(2) // krb5(2)
			,scm_from_unsigned_integer(1) // krb5_name(1)
			,SCM_UNDEFINED);
    }
  else
    INSTATHROW_SCM("unknown_oid", scm_list_n(SCM_UNDEFINED));

  //Major TODO. Probably shouldn't be exported
}

SCM gss_cred_type;
static void
gss_cred_finalizer(SCM obj)
{
  scm_assert_foreign_object_type(gss_cred_type, obj);

  gss_cred_id_t *cred = scm_foreign_object_ref(obj, 0);

  OM_uint32 minor_status;
  gss_release_cred(&minor_status, cred);
}

SCM_DEFINE(fresh_cred_lifetime, "cred->lifetime", 1, 0, 0, (SCM cred), "")
{
  scm_assert_foreign_object_type(gss_cred_type, cred);

  return scm_foreign_object_ref(cred, 1);
}

SCM gss_ctx_type;
static void
gss_ctx_finalizer(SCM obj)
{
  scm_assert_foreign_object_type(gss_ctx_type, obj);

  gss_ctx_id_t *ctx = scm_foreign_object_ref(obj, 0);
  OM_uint32 minor_status;
  gss_delete_sec_context(&minor_status
			 ,ctx
			 ,GSS_C_NO_BUFFER);
}

#define CTX_ACCESSOR(name, slot)						\
  SCM_DEFINE(fresh_ctx_##name, "ctx->" #name, 1, 0, 0, (SCM obj), "")\
  {\
  scm_assert_foreign_object_type(gss_ctx_type, obj);\
  return scm_foreign_object_ref(obj, slot);\
  }
CTX_ACCESSOR(deleg, 1)
CTX_ACCESSOR(mutual, 2)
CTX_ACCESSOR(replay, 3)
CTX_ACCESSOR(sequence, 4)
CTX_ACCESSOR(anon, 5)
CTX_ACCESSOR(trans, 6)
CTX_ACCESSOR(prot_ready, 7)
CTX_ACCESSOR(conf_avail, 8)
CTX_ACCESSOR(integ_avail, 9)
CTX_ACCESSOR(lifetime, 10)

/**
 * Builds a SCM foreign object of type gss_ctx_type
 */
SCM fresh_build_gss_ctx_type(gss_ctx_id_t ctx, OM_uint32 flags, OM_uint32 lifetime)
{
  gss_ctx_id_t *stored_ctx = scm_gc_malloc_pointerless(sizeof(gss_ctx_id_t), "gss_ctx_id_t");
  *stored_ctx = ctx;
  
  #define FLAGGED(constant) (constant & flags) ? SCM_BOOL_T : SCM_BOOL_F
  void* slots[11] = {
    ctx,
    FLAGGED(GSS_C_DELEG_FLAG),
    FLAGGED(GSS_C_MUTUAL_FLAG),    
    FLAGGED(GSS_C_REPLAY_FLAG),
    FLAGGED(GSS_C_SEQUENCE_FLAG),
    FLAGGED(GSS_C_ANON_FLAG),
    FLAGGED(GSS_C_TRANS_FLAG),
    FLAGGED(GSS_C_PROT_READY_FLAG),        
    FLAGGED(GSS_C_CONF_FLAG),
    FLAGGED(GSS_C_INTEG_FLAG),    
    scm_from_uint32(lifetime)
  };
  
  return scm_make_foreign_object_n(gss_ctx_type, 11, slots);
}

SCM_DEFINE(bind_gss_init_sec_context, "gss-init-sec-context", 5, 0, 1, (SCM cred, SCM passed_ctx, SCM target_name, SCM mech_type, SCM token, SCM rest), "")
{
  scm_assert_foreign_object_type(gss_cred_type, cred);
  SCM_ASSERT_TYPE(scm_is_false(passed_ctx) ||
		  (scm_is_true(scm_struct_p(passed_ctx)) &&
		   scm_is_eq(gss_ctx_type, scm_struct_vtable(passed_ctx)))
		  ,passed_ctx
		  ,SCM_ARG2
		  ,"gss-init-sec-context"
		  ,"#f or <gss_ctx>");
  scm_assert_foreign_object_type(gss_name_type, target_name);
  scm_assert_foreign_object_type(gss_oid_type, mech_type);
  SCM_ASSERT_TYPE(scm_is_false(token) || scm_is_bytevector(token)
		  ,token
		  ,SCM_ARG5
		  ,"gss-init-sec-context"
		  ,"#f or bytevector");

  SCM deleg_req_flag = SCM_BOOL_F
    , mutual_req_flag = SCM_BOOL_F
    , replay_det_req_flag = SCM_BOOL_F
    , sequence_req_flag = SCM_BOOL_F
    , anon_req_flag = SCM_BOOL_F
    , conf_req_flag = SCM_BOOL_F
    , integ_req_flag = SCM_BOOL_F
    , lifetime_req = scm_from_char(0);

  scm_t_keyword_arguments_flags flags;
  scm_c_bind_keyword_arguments("gss-init-sec-context"
			       ,rest
			       ,flags
			       ,scm_from_utf8_keyword("deleg"), &deleg_req_flag
			       ,scm_from_utf8_keyword("mutual"), &mutual_req_flag
			       ,scm_from_utf8_keyword("replay_det"), &replay_det_req_flag
			       ,scm_from_utf8_keyword("sequence"), &sequence_req_flag
			       ,scm_from_utf8_keyword("anon"), &anon_req_flag
			       ,scm_from_utf8_keyword("conf"), &conf_req_flag
			       ,scm_from_utf8_keyword("integ"), &integ_req_flag
			       ,scm_from_utf8_keyword("lifetime"), &lifetime_req
			       ,SCM_UNDEFINED);

#define QUICK_ASSERT_FLAG_TYPE(obj) \
  SCM_ASSERT_TYPE(scm_is_bool(obj), obj, SCM_ARGn, "gss-init-sec-context", "boolean")

  QUICK_ASSERT_FLAG_TYPE(deleg_req_flag);
  QUICK_ASSERT_FLAG_TYPE(mutual_req_flag);
  QUICK_ASSERT_FLAG_TYPE(replay_det_req_flag);
  QUICK_ASSERT_FLAG_TYPE(sequence_req_flag);
  QUICK_ASSERT_FLAG_TYPE(anon_req_flag);
  QUICK_ASSERT_FLAG_TYPE(conf_req_flag);
  QUICK_ASSERT_FLAG_TYPE(integ_req_flag);
  SCM_ASSERT_TYPE(scm_is_unsigned_integer(lifetime_req, 0, 4294967296), lifetime_req, SCM_ARGn, "gss-init-sec-context", "integer");
  
  OM_uint32 requested_flags
    = (scm_is_true(deleg_req_flag) ? GSS_C_DELEG_FLAG : 0)
    | (scm_is_true(mutual_req_flag) ? GSS_C_MUTUAL_FLAG : 0)
    | (scm_is_true(replay_det_req_flag) ? GSS_C_REPLAY_FLAG : 0)
    | (scm_is_true(sequence_req_flag) ? GSS_C_SEQUENCE_FLAG : 0)
    | (scm_is_true(anon_req_flag) ? GSS_C_ANON_FLAG : 0)
    | (scm_is_true(conf_req_flag) ? GSS_C_CONF_FLAG : 0)
    | (scm_is_true(integ_req_flag) ? GSS_C_INTEG_FLAG : 0);

  OM_uint32 major_status, minor_status;

  gss_cred_id_t *cred_id = scm_foreign_object_ref(cred, 0);

  gss_ctx_id_t ctx;
  if(scm_is_false(passed_ctx))
    ctx = GSS_C_NO_CONTEXT;
  else
    ctx = *(gss_ctx_id_t*) scm_foreign_object_ref(passed_ctx, 0);

  gss_name_t *name = scm_foreign_object_ref(target_name, 0);

  gss_OID *oid = scm_foreign_object_ref(mech_type, 0);

  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  if (scm_is_bytevector(token))
    {
      input_token.length = SCM_BYTEVECTOR_LENGTH(token);
      input_token.value = SCM_BYTEVECTOR_CONTENTS(token);
    }

  gss_buffer_desc output_token;
  OM_uint32 actual_flags;
  OM_uint32 actual_lifetime;
  major_status = gss_init_sec_context(&minor_status
				      ,*cred_id
				      ,&ctx
				      ,*name
				      ,*oid
				      ,requested_flags
				      ,scm_to_uint32(lifetime_req)
				      ,GSS_C_NO_CHANNEL_BINDINGS
				      ,&input_token
				      ,NULL // actual_mech
				      ,&output_token
				      ,&actual_flags
				      ,&actual_lifetime);
  
  HANDLE_GSS_ERROR(major_status, minor_status, oid);
  
  SCM return_ctx = fresh_build_gss_ctx_type(ctx, actual_flags, actual_lifetime);
  
  SCM return_token = SCM_BOOL_F;
  if (output_token.length > 0)
    {
      return_token = scm_c_make_bytevector(output_token.length);
      memcpy(SCM_BYTEVECTOR_CONTENTS(return_token)
	     ,output_token.value
	     ,output_token.length);
    }
  gss_release_buffer(&minor_status, &output_token);

  SCM continue_needed = SCM_BOOL_F;
  if (major_status & GSS_S_CONTINUE_NEEDED)
    continue_needed = SCM_BOOL_T;

  return scm_values(scm_list_3(return_ctx, continue_needed, return_token));
}

SCM_DEFINE(bind_gss_accept_sec_context, "gss-accept-sec-context", 3, 0, 0, (SCM passed_cred, SCM passed_ctx, SCM passed_token), "")
{
  scm_assert_foreign_object_type(gss_cred_type, passed_cred);  
  SCM_ASSERT_TYPE(scm_is_false(passed_ctx) ||
		  (scm_is_true(scm_struct_p(passed_ctx)) &&
		   scm_is_eq(gss_ctx_type, scm_struct_vtable(passed_ctx)))
		  ,passed_ctx
		  ,SCM_ARG2
		  ,"gss-accept-sec-context"
		  ,"#f or <gss_ctx>");
  SCM_ASSERT_TYPE(scm_is_bytevector(passed_token)
		  ,passed_token
		  ,SCM_ARG3
		  ,"gss-accept-sec-context"
		  ,"bytevector");
  
  gss_ctx_id_t ctx;
  if(scm_is_false(passed_ctx))
    ctx = GSS_C_NO_CONTEXT;
  else
    ctx = *(gss_ctx_id_t*) scm_foreign_object_ref(passed_ctx, 0);
  
  gss_cred_id_t *accept_cred = scm_foreign_object_ref(passed_cred, 0);
  
  gss_buffer_desc input_token = {
    .length = SCM_BYTEVECTOR_LENGTH(passed_token),
    .value = SCM_BYTEVECTOR_CONTENTS(passed_token)
  };

  OM_uint32 major_status, minor_status;
  gss_name_t peer_name;
  gss_buffer_desc output_token;
  OM_uint32 actual_flags;
  OM_uint32 actual_lifetime;
  gss_OID mech_type;
  major_status = gss_accept_sec_context(&minor_status
					,&ctx
					,*accept_cred
					,&input_token
					,GSS_C_NO_CHANNEL_BINDINGS
					,&peer_name
					,&mech_type
					,&output_token
					,&actual_flags
					,&actual_lifetime
					,NULL); // delegated_cred_handle
  
  HANDLE_GSS_ERROR(major_status, minor_status, &mech_type);
  
  SCM return_ctx = fresh_build_gss_ctx_type(ctx
					    ,actual_flags
					    ,actual_lifetime);

  SCM continue_needed = SCM_BOOL_F;
  if (major_status & GSS_S_CONTINUE_NEEDED)
    continue_needed = SCM_BOOL_T;

  SCM return_token = SCM_BOOL_F;
  if (output_token.length > 0)
    {
      return_token = scm_c_make_bytevector(output_token.length);
      memcpy(SCM_BYTEVECTOR_CONTENTS(return_token)
	     ,output_token.value
	     ,output_token.length);
    }
  gss_release_buffer(&minor_status, &output_token);  

  return scm_values(scm_list_3(return_ctx
			       ,continue_needed
			       ,return_token));
}

SCM_DEFINE(bind_gss_acquire_cred, "gss-acquire-cred", 4, 0, 0, (SCM desired_name, SCM lifetime_req, SCM desired_mechs, SCM cred_usage), "")
{
  scm_assert_foreign_object_type(gss_name_type, desired_name);

  SCM_ASSERT_TYPE(scm_is_integer(lifetime_req)
		  ,lifetime_req
		  ,SCM_ARG2
		  ,"gss-acquire-cred"
		  ,"integer");
  SCM_ASSERT_TYPE(scm_is_true(scm_list_p(desired_mechs))
		  ,desired_mechs
		  ,SCM_ARG3
		  ,"gss-acquire-cred"
		  ,"list of <gss_oid>");

  void require_gss_oid (SCM list) {
    while (!scm_is_null(list))
      {
	scm_assert_foreign_object_type(gss_oid_type
				       , scm_car(list));
	
	list = scm_cdr(list);
      }
  }
  require_gss_oid(desired_mechs);

  gss_cred_usage_t gss_cred_usage;
  if (scm_is_eq(cred_usage, scm_from_utf8_symbol("initiate-and-accept")))
    gss_cred_usage = 0;
  else if  (scm_is_eq(cred_usage, scm_from_utf8_symbol("initiate-only")))
    gss_cred_usage = 1;
  else if  (scm_is_eq(cred_usage, scm_from_utf8_symbol("accept-only")))
    gss_cred_usage = 2;
  else
    SCM_ASSERT_TYPE(0
		    ,cred_usage
		    ,SCM_ARG4
		    ,"gss-acquire-cred"
		    ,"one of: 'initiate-and-accept, 'initiate-only, or 'accept-only");

  // Populate an oid set of mechanisms
  OM_uint32 minor_status;

  gss_OID_set oid_set;  
  if (gss_create_empty_oid_set(&minor_status, &oid_set) != GSS_S_COMPLETE)
    INSTATHROW_SCM("failure", scm_list_1(scm_from_uint32(minor_status)));

  gss_OID *oid;
  SCM remaining_mechs = desired_mechs;
  while (!scm_is_null(remaining_mechs))
    {
      SCM this_oid_foreign_object = scm_car(remaining_mechs);
      oid = scm_foreign_object_ref(this_oid_foreign_object, 0);
      

      if (GSS_S_COMPLETE != gss_add_oid_set_member(&minor_status
						   ,*oid
						   ,&oid_set))
	{
	  gss_release_oid_set(&minor_status, &oid_set);
	  INSTATHROW_SCM("failure", scm_list_1(scm_from_uint32(minor_status)));
	}
      
      remaining_mechs = scm_cdr(remaining_mechs);
    }

  gss_name_t *internal_name = scm_foreign_object_ref(desired_name, 0);
  gss_cred_id_t output_cred;
  gss_OID_set actual_mechs;
  OM_uint32 actual_lifetime;
  OM_uint32 major_status = gss_acquire_cred(&minor_status
					    ,*internal_name
					    ,scm_to_uint32(lifetime_req)
					    ,oid_set
					    ,gss_cred_usage
					    ,&output_cred
					    ,&actual_mechs
					    ,&actual_lifetime);


  OM_uint32 oid_release_minor_status;
  gss_release_oid_set(&oid_release_minor_status, &oid_set);

  // Try and get some additional failure information if only one
  // mechanism was passed
  if (scm_is_true(scm_num_eq_p(scm_length(desired_mechs)
			       ,scm_from_char(1))))
    {
      HANDLE_GSS_ERROR(major_status, minor_status, oid);
    }
  else
    HANDLE_GSS_ERROR(major_status, minor_status, NULL);
  
  // TODO: do we want to save these mechanisms for the user?
  if (actual_mechs != NULL)
    gss_release_oid_set(&minor_status, &actual_mechs);
  
  gss_cred_id_t *saved_cred = scm_gc_malloc_pointerless(sizeof(gss_cred_id_t)
							,"gss_cred");
  if (output_cred != NULL)
    *saved_cred = output_cred;
  
  return scm_make_foreign_object_2(gss_cred_type
				   ,saved_cred
				   ,scm_from_uint32(actual_lifetime));
}

SCM_DEFINE(bind_gss_display_name, "gss-display-name", 1, 0, 0, (SCM obj), "")
{
  scm_assert_foreign_object_type(gss_name_type, obj);

  gss_name_t *name = scm_foreign_object_ref(obj, 0);

  OM_uint32 minor_status;
  gss_buffer_desc output_name_buffer;
  gss_OID output_name_type;
  OM_uint32 major_status = gss_display_name(&minor_status, *name, &output_name_buffer, &output_name_type);
  HANDLE_GSS_ERROR(major_status, minor_status, NULL);

  SCM result = scm_c_make_bytevector(output_name_buffer.length);
  memcpy(SCM_BYTEVECTOR_CONTENTS(result)
	 ,output_name_buffer.value
	 ,output_name_buffer.length);
  gss_release_buffer(&minor_status, &output_name_buffer);
  
    return result;
}

SCM_DEFINE(bind_gss_import_name, "gss-import-name", 2, 0, 0, (SCM name, SCM name_type_oid), "")
{

  SCM_ASSERT_TYPE(scm_is_true(scm_bytevector_p(name))
	     ,name
	     ,SCM_ARG1
	     ,"gss-import-name"
	     ,"bytevector");

  scm_assert_foreign_object_type(gss_oid_type, name_type_oid);

  gss_buffer_desc input_name_buffer = {
    .length = SCM_BYTEVECTOR_LENGTH(name),
    .value = SCM_BYTEVECTOR_CONTENTS(name)
  };

  if (!scm_is_eq(name_type_oid, scm_variable_ref(gss_oid_GSS_KRB5_NT_PRINCIPAL_NAME)))
      INSTATHROW("bad_mechanism");

  gss_name_t output_name;
  OM_uint32 minor_status;
  OM_uint32 major_status = gss_import_name(&minor_status
					   ,&input_name_buffer
					   ,GSS_KRB5_NT_PRINCIPAL_NAME
					   ,&output_name);
  HANDLE_GSS_ERROR(major_status, minor_status, &GSS_KRB5_NT_PRINCIPAL_NAME);

  gss_name_t *saved_name = scm_gc_malloc_pointerless(sizeof(gss_name_t), "gss_name_t");
  *saved_name = output_name;
  
  return scm_make_foreign_object_1(gss_name_type, saved_name);
}

SCM_DEFINE(bind_gss_wrap, "gss-wrap", 3, 0, 0, (SCM passed_ctx, SCM conf_req, SCM msg), "")
{
  SCM conf_and_integ = scm_from_utf8_symbol("confidentiality-and-integrity");
  SCM integ_only = scm_from_utf8_symbol("integrity-only");
  
  scm_assert_foreign_object_type(gss_ctx_type, passed_ctx);
  SCM_ASSERT_TYPE(scm_is_symbol(conf_req) &&
		  (scm_is_eq(conf_req, conf_and_integ)
		   || scm_is_eq(conf_req, integ_only))
		  ,conf_req
		  ,SCM_ARG2
		  ,"gss-wrap"
		  ,"either 'confidentiality-and-integrity or 'integrity-only");
  SCM_ASSERT_TYPE(scm_is_bytevector(msg)
		  ,msg
		  ,SCM_ARG3
		  ,"gss-wrap"
		  ,"bytevector");

  gss_ctx_id_t *ctx = scm_foreign_object_ref(passed_ctx, 0);

  int conf_req_flag = 1;
  if (scm_is_eq(conf_req, integ_only))
    conf_req_flag = 0;

  gss_buffer_desc input_message = {
    .length = SCM_BYTEVECTOR_LENGTH(msg),
    .value = SCM_BYTEVECTOR_CONTENTS(msg)
  };

  OM_uint32 major_status, minor_status;
  int conf_state;
  gss_buffer_desc output_message;

  major_status = gss_wrap(&minor_status
			  ,*ctx
			  ,conf_req_flag
			  ,GSS_C_QOP_DEFAULT
			  ,&input_message
			  ,&conf_state
			  ,&output_message);
  HANDLE_GSS_ERROR(major_status, minor_status, NULL);

  SCM return_msg = scm_c_make_bytevector(output_message.length);
  memcpy(SCM_BYTEVECTOR_CONTENTS(return_msg)
	 ,output_message.value
	 ,output_message.length);
  gss_release_buffer(&minor_status, &output_message);

  SCM return_conf_flag = conf_state ? conf_and_integ : integ_only;

  return scm_cons(return_msg, return_conf_flag);
}

SCM_DEFINE(bind_gss_unwrap, "gss-unwrap", 2, 0, 0, (SCM passed_ctx, SCM msg), "")
{
  SCM conf_and_integ = scm_from_utf8_symbol("confidentiality-and-integrity");
  SCM integ_only = scm_from_utf8_symbol("integrity-only");
  
  scm_assert_foreign_object_type(gss_ctx_type, passed_ctx);
  SCM_ASSERT_TYPE(scm_is_bytevector(msg)
		  ,msg
		  ,SCM_ARG2
		  ,"gss-unwrap"
		  ,"bytevector");

  gss_ctx_id_t *ctx = scm_foreign_object_ref(passed_ctx, 0);

  gss_buffer_desc input_message = {
    .length = SCM_BYTEVECTOR_LENGTH(msg),
    .value = SCM_BYTEVECTOR_CONTENTS(msg)
  };

  OM_uint32 major_status, minor_status;
  int conf_state;
  gss_buffer_desc output_message;

  major_status = gss_unwrap(&minor_status
			    ,*ctx
			    ,&input_message
			    ,&output_message
			    ,&conf_state
			    ,NULL);
  
  HANDLE_GSS_ERROR(major_status, minor_status, NULL);

  SCM return_msg = scm_c_make_bytevector(output_message.length);
  memcpy(SCM_BYTEVECTOR_CONTENTS(return_msg)
	 ,output_message.value
	 ,output_message.length);
  gss_release_buffer(&minor_status, &output_message);

  SCM return_conf_flag = conf_state ? conf_and_integ : integ_only;

  return scm_cons(return_msg, return_conf_flag);
}


void
init(void)
{
  gss_name_type =
    scm_make_foreign_object_type(scm_from_utf8_symbol("gss_name")
				 ,scm_list_1(scm_from_utf8_symbol("data"))
				 ,gss_name_finalizer);
  
  gss_oid_type =
    scm_make_foreign_object_type(scm_from_utf8_symbol("gss_oid")
				 ,scm_list_1(scm_from_utf8_symbol("data"))
				 ,NULL);
  
  gss_cred_type =
    scm_make_foreign_object_type(scm_from_utf8_symbol("gss_cred")
				 ,scm_list_2(scm_from_utf8_symbol("cred")
					     ,scm_from_utf8_symbol("lifetime"))
				 ,gss_cred_finalizer);

  gss_ctx_type =
    scm_make_foreign_object_type(scm_from_utf8_symbol("gss_ctx")
				 ,scm_list_n(scm_from_utf8_symbol("ctx")
					     ,scm_from_utf8_symbol("deleg")
					     ,scm_from_utf8_symbol("mutual")
					     ,scm_from_utf8_symbol("replay")
					     ,scm_from_utf8_symbol("sequence")
					     ,scm_from_utf8_symbol("anon")
					     ,scm_from_utf8_symbol("trans")
					     ,scm_from_utf8_symbol("prot_ready")
					     ,scm_from_utf8_symbol("conf_avail")
					     ,scm_from_utf8_symbol("integ_avail")
					     ,scm_from_utf8_symbol("lifetime")
					     ,SCM_UNDEFINED)
				 ,gss_ctx_finalizer);
					     

					     
  #include "snarfed_includeme.h"
}
