#include "hexlab/loaders/jvm.hpp"
#include <stdexcept>

namespace hexlab {
namespace {
struct SignatureFailure { Error error; };
struct SignatureReader {
    std::string_view text;
    std::stop_token stop;
    std::size_t position=0;
    JvmGenericSignature result;
    [[noreturn]] void fail(const char *message) const {
        throw SignatureFailure{{ErrorCode::malformed,message}};
    }
    char peek() const { return position<text.size()?text[position]:'\0'; }
    bool take(char byte) { if(peek()!=byte)return false;++position;return true; }
    void expect(char byte) { if(!take(byte))fail("Generic signature has a missing delimiter"); }
    std::uint32_t node(JvmGenericNodeKind kind,std::size_t start,std::string name={}) {
        if(stop.stop_requested())throw SignatureFailure{{ErrorCode::canceled,"Generic signature parsing canceled"}};
        if(result.nodes.size()>=1024)throw SignatureFailure{{ErrorCode::resource_limit,"Generic signature exceeds 1024 syntax nodes"}};
        const auto index=static_cast<std::uint32_t>(result.nodes.size());
        result.nodes.push_back({kind,static_cast<std::uint32_t>(start),0,std::move(name),{}});
        return index;
    }
    void finish(std::uint32_t index) { result.nodes[index].text_size=static_cast<std::uint32_t>(position-result.nodes[index].text_offset); }
    void child(std::uint32_t parent,std::uint32_t index) { result.nodes[parent].children.push_back(index); }
    std::string identifier() {
        const auto start=position;
        while(position<text.size()) {
            const auto byte=peek();
            if(byte=='.'||byte==';'||byte=='['||byte=='/'||byte=='<'||byte=='>'||byte==':'||byte=='\0')break;
            ++position;
        }
        if(start==position)fail("Generic signature has an empty identifier");
        return std::string(text.substr(start,position-start));
    }
    void arguments(std::uint32_t segment,unsigned depth) {
        if(!take('<'))return;
        if(peek()=='>')fail("Generic signature has empty type arguments");
        do {
            const auto start=position;
            auto kind=JvmGenericNodeKind::exact_argument;
            if(take('*'))kind=JvmGenericNodeKind::unbounded_argument;
            else if(take('+'))kind=JvmGenericNodeKind::extends_argument;
            else if(take('-'))kind=JvmGenericNodeKind::super_argument;
            const auto argument=node(kind,start);child(segment,argument);
            if(kind!=JvmGenericNodeKind::unbounded_argument)child(argument,type(depth+1,true));
            finish(argument);
        }while(peek()!='>'&&position<text.size());
        expect('>');
    }
    std::uint32_t type(unsigned depth,bool reference_only) {
        if(depth>32)throw SignatureFailure{{ErrorCode::resource_limit,"Generic signature exceeds 32 nested type levels"}};
        const auto start=position;const auto tag=peek();
        if(tag=='L') {
            ++position;const auto root=node(JvmGenericNodeKind::class_type,start);
            auto segment_start=position;auto name=identifier();
            while(take('/')){name+='/';name+=identifier();}
            auto segment=node(JvmGenericNodeKind::class_segment,segment_start,std::move(name));child(root,segment);
            arguments(segment,depth);finish(segment);
            while(take('.')) {
                segment_start=position;name=identifier();segment=node(JvmGenericNodeKind::class_segment,segment_start,std::move(name));child(root,segment);
                arguments(segment,depth);finish(segment);
            }
            expect(';');finish(root);return root;
        }
        if(tag=='T') {
            ++position;auto name=identifier();expect(';');const auto root=node(JvmGenericNodeKind::type_variable,start,std::move(name));finish(root);return root;
        }
        if(tag=='[') {
            ++position;const auto root=node(JvmGenericNodeKind::array_type,start);child(root,type(depth+1,false));finish(root);return root;
        }
        if(!reference_only&&(tag=='B'||tag=='C'||tag=='D'||tag=='F'||tag=='I'||tag=='J'||tag=='S'||tag=='Z')) {
            ++position;const auto root=node(JvmGenericNodeKind::primitive,start,std::string(1,tag));finish(root);return root;
        }
        fail("Generic signature has an invalid type production");
    }
    void formals(std::uint32_t root) {
        if(!take('<'))return;
        if(peek()=='>')fail("Generic signature has empty formal type parameters");
        do {
            const auto start=position;auto name=identifier();const auto formal=node(JvmGenericNodeKind::type_parameter,start,std::move(name));child(root,formal);
            const auto bound=node(JvmGenericNodeKind::class_bound,position);expect(':');child(formal,bound);
            if(peek()=='L'||peek()=='T'||peek()=='[') {
                // ClassBound's reference is optional. A following formal's
                // identifier can itself begin L/T; a malformed reference
                // alternative must not consume that next declaration.
                const auto saved_position=position,saved_nodes=result.nodes.size();
                try { child(bound,type(0,true)); }
                catch(const SignatureFailure& failure) {
                    if(failure.error.code!=ErrorCode::malformed)throw;
                    position=saved_position;result.nodes.resize(saved_nodes);
                }
            }
            finish(bound);
            while(peek()==':') { const auto next=node(JvmGenericNodeKind::interface_bound,position);++position;child(formal,next);child(next,type(0,true));finish(next); }
            finish(formal);
        }while(peek()!='>'&&position<text.size());
        expect('>');
    }
    JvmGenericSignature read(JvmGenericSignatureKind kind) {
        result.kind=kind;
        const auto root=node(kind==JvmGenericSignatureKind::class_signature?JvmGenericNodeKind::class_signature:
                             kind==JvmGenericSignatureKind::method_signature?JvmGenericNodeKind::method_signature:JvmGenericNodeKind::field_signature,0);
        if(kind==JvmGenericSignatureKind::field_signature)child(root,type(0,true));
        else {
            formals(root);
            if(kind==JvmGenericSignatureKind::class_signature) {
                auto wrapper=node(JvmGenericNodeKind::superclass,position);child(root,wrapper);
                if(peek()!='L')fail("Generic class superclass must be a class type");child(wrapper,type(0,true));finish(wrapper);
                while(position<text.size()) { wrapper=node(JvmGenericNodeKind::superinterface,position);child(root,wrapper);if(peek()!='L')fail("Generic superinterface must be a class type");child(wrapper,type(0,true));finish(wrapper); }
            }else {
                const auto parameters=node(JvmGenericNodeKind::parameters,position);child(root,parameters);expect('(');
                while(peek()!=')'&&position<text.size())child(parameters,type(0,false));
                expect(')');finish(parameters);
                const auto value=node(JvmGenericNodeKind::result,position);child(root,value);
                if(take('V')){const auto empty=node(JvmGenericNodeKind::void_type,position-1);finish(empty);child(value,empty);}else child(value,type(0,false));finish(value);
                while(take('^')){const auto raised=node(JvmGenericNodeKind::throws_type,position-1);child(root,raised);if(peek()!='L'&&peek()!='T')fail("Generic throws signature must be a class or type variable");child(raised,type(0,true));finish(raised);}
            }
        }
        if(position!=text.size())fail("Generic signature has trailing bytes");finish(root);return std::move(result);
    }
};
}
Result<JvmGenericSignature> parse_jvm_generic_signature(std::string_view text,JvmGenericSignatureKind kind,std::stop_token stop) try {
    if(text.empty())return Error{ErrorCode::malformed,"Generic signature is empty"};
    if(text.size()>65535)return Error{ErrorCode::resource_limit,"Generic signature exceeds 65535 bytes"};
    if(kind!=JvmGenericSignatureKind::class_signature&&kind!=JvmGenericSignatureKind::method_signature&&kind!=JvmGenericSignatureKind::field_signature)
        return Error{ErrorCode::invalid_argument,"Unknown generic signature grammar kind"};
    return SignatureReader{text,stop}.read(kind);
} catch(const SignatureFailure& failure) {return failure.error;}
  catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate generic signature tree"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"Generic signature tree exceeds container limits"};}
}
